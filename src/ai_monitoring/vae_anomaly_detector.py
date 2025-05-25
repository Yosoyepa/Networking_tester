\
import tensorflow as tf
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib
import os
import logging
import traceback # Added import

logger = logging.getLogger(__name__)

# Define the subclassed VAE model
class VAE(tf.keras.Model):
    def __init__(self, encoder, decoder, input_dim, name="vae", **kwargs):
        super().__init__(name=name, **kwargs)
        self.encoder = encoder
        self.decoder = decoder
        self.input_dim = input_dim # Store for loss calculation
        
        self.total_loss_tracker = tf.keras.metrics.Mean(name="total_loss")
        self.reconstruction_loss_tracker = tf.keras.metrics.Mean(name="reconstruction_loss")
        self.kl_loss_tracker = tf.keras.metrics.Mean(name="kl_loss")

    @property
    def metrics(self):
        return [
            self.total_loss_tracker,
            self.reconstruction_loss_tracker,
            self.kl_loss_tracker,
        ]

    def call(self, inputs, training=False): # Add training flag
        z_mean, z_log_var, z = self.encoder(inputs, training=training) # Pass training flag
        reconstruction = self.decoder(z, training=training) # Pass training flag
        # For train_step, we need z_mean, z_log_var. For predict, only reconstruction.
        # This call signature is used by train_step, test_step, and predict.
        return reconstruction, z_mean, z_log_var

    def train_step(self, data):
        if isinstance(data, tuple):
            # Handles data in the form of (x, y) or (x, y, sample_weight)
            # For unsupervised VAE, y is typically x or not used if x is the target.
            # If fit is called as model.fit(x_train, x_train, ...), data will be (x_train_batch, x_train_batch)
            inputs = data[0]
        else:
            # Handles data in the form of x (for model.fit(x_train, ...))
            inputs = data

        with tf.GradientTape() as tape:
            reconstruction, z_mean, z_log_var = self(inputs, training=True)

            reconstruction_loss = tf.keras.ops.mean(tf.keras.ops.square(inputs - reconstruction))
            reconstruction_loss *= tf.cast(self.input_dim, dtype=reconstruction_loss.dtype)

            kl_loss = -0.5 * tf.keras.ops.sum(
                1 + z_log_var - tf.keras.ops.square(z_mean) - tf.keras.ops.exp(z_log_var),
                axis=-1,
            )
            kl_loss = tf.keras.ops.mean(kl_loss)
            total_loss = reconstruction_loss + kl_loss

        grads = tape.gradient(total_loss, self.trainable_weights)
        self.optimizer.apply_gradients(zip(grads, self.trainable_weights))

        self.total_loss_tracker.update_state(total_loss)
        self.reconstruction_loss_tracker.update_state(reconstruction_loss)
        self.kl_loss_tracker.update_state(kl_loss)
        return {m.name: m.result() for m in self.metrics}

    def test_step(self, data):
        if isinstance(data, tuple):
            inputs = data[0]
        else:
            inputs = data
        
        reconstruction, z_mean, z_log_var = self(inputs, training=False)

        reconstruction_loss = tf.keras.ops.mean(tf.keras.ops.square(inputs - reconstruction))
        reconstruction_loss *= tf.cast(self.input_dim, dtype=reconstruction_loss.dtype)

        kl_loss = -0.5 * tf.keras.ops.sum(
            1 + z_log_var - tf.keras.ops.square(z_mean) - tf.keras.ops.exp(z_log_var),
            axis=-1,
        )
        kl_loss = tf.keras.ops.mean(kl_loss)
        total_loss = reconstruction_loss + kl_loss

        self.total_loss_tracker.update_state(total_loss)
        self.reconstruction_loss_tracker.update_state(reconstruction_loss)
        self.kl_loss_tracker.update_state(kl_loss)
        return {m.name: m.result() for m in self.metrics}


class VAEAnomalyDetector:
    def __init__(self, input_dim, latent_dim=2, intermediate_dim=32, anomaly_threshold_std_dev=2.0, random_state=42):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.intermediate_dim = intermediate_dim
        self.anomaly_threshold_std_dev = anomaly_threshold_std_dev
        self.random_state = random_state
        
        np.random.seed(self.random_state)
        tf.random.set_seed(self.random_state)

        self.scaler = StandardScaler()
        self.encoder = None # Will be part of the VAE model
        self.decoder = None # Will be part of the VAE model
        self.vae = None     # This will be the subclassed VAE model
        self.history = None
        self.reconstruction_threshold = None
        self.trained_features = None

        self._build_model()

    def _build_model(self):
        # Encoder
        encoder_inputs = tf.keras.layers.Input(shape=(self.input_dim,), name='encoder_input')
        h = tf.keras.layers.Dense(self.intermediate_dim, activation='relu')(encoder_inputs)
        z_mean = tf.keras.layers.Dense(self.latent_dim, name='z_mean')(h)
        z_log_var = tf.keras.layers.Dense(self.latent_dim, name='z_log_var')(h)

        # Sampling function (relies on global tf.random.set_seed)
        def sampling(args):
            z_mean_s, z_log_var_s = args
            batch = tf.keras.ops.shape(z_mean_s)[0]
            dim = tf.keras.ops.shape(z_mean_s)[1]
            # Corrected to use tf.random.normal for random number generation
            epsilon = tf.random.normal(shape=(batch, dim), mean=0.0, stddev=1.0) 
            return z_mean_s + tf.keras.ops.exp(0.5 * z_log_var_s) * epsilon

        z = tf.keras.layers.Lambda(sampling, output_shape=(self.latent_dim,), name='z')([z_mean, z_log_var])
        
        # Define encoder as a Keras Functional model
        encoder_model = tf.keras.models.Model(encoder_inputs, [z_mean, z_log_var, z], name='encoder')

        # Decoder
        latent_inputs = tf.keras.layers.Input(shape=(self.latent_dim,), name='z_sampling')
        x = tf.keras.layers.Dense(self.intermediate_dim, activation='relu')(latent_inputs)
        decoder_outputs = tf.keras.layers.Dense(self.input_dim, activation='sigmoid')(x)
        
        # Define decoder as a Keras Functional model
        decoder_model = tf.keras.models.Model(latent_inputs, decoder_outputs, name='decoder')

        # VAE (subclassed model)
        self.vae = VAE(encoder_model, decoder_model, self.input_dim)
        self.vae.compile(optimizer=tf.keras.optimizers.Adam())
        
        # Store encoder and decoder if direct access is needed later, though VAE contains them
        self.encoder = encoder_model
        self.decoder = decoder_model

        logger.info(f"VAE model (subclassed) built: input_dim={self.input_dim}, latent_dim={self.latent_dim}, intermediate_dim={self.intermediate_dim}")

    def train(self, data: pd.DataFrame, epochs=50, batch_size=32):
        if not isinstance(data, pd.DataFrame):
            raise ValueError("Input data must be a pandas DataFrame.")
        if data.empty:
            logger.error("Training data is empty.")
            return

        self.trained_features = data.columns.tolist()
        logger.info(f"Starting VAE training with features: {self.trained_features}")
        
        x_train = self.scaler.fit_transform(data)

        logger.info(f"Training VAE with {x_train.shape[0]} samples, {epochs} epochs, batch_size={batch_size}.")
        # For unsupervised VAE, fit with x_train as both input and target, or just input if train_step handles it
        self.history = self.vae.fit(x_train, x_train, epochs=epochs, batch_size=batch_size, shuffle=True, validation_split=0.1, verbose=1)

        logger.info("Calculating reconstruction threshold...")
        # predict() will call VAE.call which returns (reconstruction, z_mean, z_log_var)
        predictions_tuple = self.vae.predict(x_train)
        x_train_pred = predictions_tuple[0] # First element is the reconstruction

        mse_train = np.mean(np.power(x_train - x_train_pred, 2), axis=1)
        
        self.reconstruction_threshold = np.mean(mse_train) + self.anomaly_threshold_std_dev * np.std(mse_train)
        logger.info(f"Reconstruction threshold set to: {self.reconstruction_threshold:.4f} (mean_mse={np.mean(mse_train):.4f}, std_mse={np.std(mse_train):.4f})")
        logger.info("VAE training completed.")

    def predict(self, data: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        if self.vae is None:
            raise ValueError("Model has not been trained or loaded.")
        if not isinstance(data, pd.DataFrame):
            raise ValueError("Input data must be a pandas DataFrame.")
        if data.empty:
            logger.warning("Prediction data is empty.")
            return np.array([]), np.array([])

        if self.trained_features:
            missing_cols = set(self.trained_features) - set(data.columns)
            if missing_cols:
                raise ValueError(f"Missing columns in prediction data: {missing_cols}")
            data_reordered = data[self.trained_features]
        else:
            data_reordered = data

        x_eval = self.scaler.transform(data_reordered)
        
        # predict() will call VAE.call
        reconstructions_tuple = self.vae.predict(x_eval)
        reconstructions = reconstructions_tuple[0] # First element is reconstruction

        mse_eval = np.mean(np.power(x_eval - reconstructions, 2), axis=1)

        anomalies = (mse_eval > self.reconstruction_threshold).astype(int)
        logger.debug(f"Predictions made. MSE sample: {mse_eval[:5]}. Anomalies identified: {np.sum(anomalies)}/{len(anomalies)}")
        return anomalies, mse_eval

    def save(self, model_path_prefix: str):
        if self.vae is None:
            logger.error("No model to save.")
            return

        model_dir = os.path.dirname(model_path_prefix)
        if model_dir and not os.path.exists(model_dir):
            os.makedirs(model_dir, exist_ok=True)

        # Corrected filename for save_weights
        weights_filename = f"{model_path_prefix}.weights.h5"
        self.vae.save_weights(weights_filename)
        joblib.dump(self.scaler, f"{model_path_prefix}_scaler.joblib")

        metadata = {
            'input_dim': self.input_dim,
            'latent_dim': self.latent_dim,
            'intermediate_dim': self.intermediate_dim,
            'anomaly_threshold_std_dev': self.anomaly_threshold_std_dev,
            'reconstruction_threshold': self.reconstruction_threshold,
            'trained_features': self.trained_features,
            'random_state': self.random_state
        }
        joblib.dump(metadata, f"{model_path_prefix}_metadata.joblib")
        logger.info(f"VAE model (subclassed weights, scaler, metadata) saved with prefix: {model_path_prefix}. Weights to: {weights_filename}")

    @classmethod
    def load(cls, model_path_prefix: str): # model_path_prefix is the directory like /app/data/mlops_artifacts/models/qos_anomaly_vae_e2e_test/1.0.0/
        # Infer model_name from the directory structure
        # e.g., .../models/qos_anomaly_vae_e2e_test/1.0.0/ -> qos_anomaly_vae_e2e_test
        # Ensure model_path_prefix ends with a separator for dirname to work as expected if it's already a directory path
        normalized_path = model_path_prefix.rstrip(os.sep)
        model_name = os.path.basename(os.path.dirname(normalized_path)) # Gets 'qos_anomaly_vae_e2e_test'
        
        # If the model_path_prefix itself is the model name (e.g. for local testing save/load)
        # then os.path.dirname would give the parent directory.
        # A better way might be to expect the files to be directly in model_path_prefix using a fixed base name
        # or pass model_name explicitly.
        # For now, let's assume the structure from the service: model_path_prefix is the versioned directory.
        # The files inside are named based on the model_name.

        # The files in the directory are named like:
        # qos_anomaly_vae_e2e_test.weights.h5
        # qos_anomaly_vae_e2e_test_metadata.joblib
        # qos_anomaly_vae_e2e_test_scaler.joblib
        # So, the 'model_name' derived above is the correct base for filenames.

        metadata_filename = f"{model_name}_metadata.joblib"
        weights_filename = f"{model_name}.weights.h5" # As per save method and ls output
        scaler_filename = f"{model_name}_scaler.joblib"

        metadata_path = os.path.join(model_path_prefix, metadata_filename)
        weights_path = os.path.join(model_path_prefix, weights_filename)
        scaler_path = os.path.join(model_path_prefix, scaler_filename)

        if not all(os.path.exists(p) for p in [metadata_path, weights_path, scaler_path]):
            logger.error(f"One or more VAE artifact files not found. Searched for:\\n- Metadata: {metadata_path}\\n- Weights: {weights_path}\\n- Scaler: {scaler_path}")
            # Log what is actually in the directory for debugging
            if os.path.exists(model_path_prefix):
                logger.error(f"Contents of directory {model_path_prefix}: {os.listdir(model_path_prefix)}")
            else:
                logger.error(f"Directory {model_path_prefix} does not exist.")
            return None
        try:
            metadata = joblib.load(metadata_path)
            scaler = joblib.load(scaler_path)

            instance = cls(
                input_dim=metadata['input_dim'],
                latent_dim=metadata['latent_dim'],
                intermediate_dim=metadata['intermediate_dim'],
                anomaly_threshold_std_dev=metadata.get('anomaly_threshold_std_dev', 3.0),
                random_state=metadata.get('random_state', None)
            )
            instance.scaler = scaler
            instance.trained_features = metadata.get('trained_features', None)
            instance.reconstruction_threshold = metadata.get('reconstruction_threshold', None)

            # Explicitly build the VAE model before loading weights
            if instance.vae is not None:
                # The input shape for build should be (batch_size, num_features)
                # We use None for batch_size to indicate it can be variable.
                build_shape = (None, instance.input_dim)
                instance.vae.build(input_shape=build_shape)
                logger.info(f"VAE model explicitly built with input_shape={build_shape} before loading weights.")
            else:
                logger.error("VAE model (self.vae) is None before build attempt. This should not happen.")
                # This case should ideally not be reached if __init__ works correctly.
                # Re-create the VAE model if it's somehow None
                instance._build_vae_model() # Assuming _build_vae_model can be called again
                if instance.vae is not None:
                    instance.vae.build(input_shape=build_shape)
                    logger.info(f"Re-built and explicitly built VAE model with input_shape={build_shape}.")
                else:
                    raise RuntimeError("Failed to create or build the VAE model during load.")


            instance.vae.load_weights(weights_path)
            logger.info(f"VAE model loaded successfully from prefix: {model_path_prefix}")
            return instance
        except Exception as e:
            logger.error(f"Error loading VAE model from {model_path_prefix}: {e}")
            logger.error(traceback.format_exc())
            return None

if __name__ == '__main__':
    # Example Usage (Illustrative)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    logger.info("Starting VAE Anomaly Detector example with subclassed VAE model...")

    # Create dummy data
    n_samples = 1000
    n_features = 5
    X_train_normal = pd.DataFrame(np.random.rand(n_samples, n_features), columns=[f'feature{i+1}' for i in range(n_features)])
    
    # Introduce some anomalies for testing prediction
    X_test_normal = pd.DataFrame(np.random.rand(100, n_features), columns=X_train_normal.columns)
    X_test_anomalies = pd.DataFrame(np.random.rand(20, n_features) * 2 + 0.5, columns=X_train_normal.columns) # Slightly different distribution
    X_test = pd.concat([X_test_normal, X_test_anomalies], ignore_index=True)
    y_test_true = np.array([0]*100 + [1]*20) # 0 for normal, 1 for anomaly

    # Initialize and train
    input_dim = X_train_normal.shape[1]
    vae_detector = VAEAnomalyDetector(input_dim=input_dim, latent_dim=2, intermediate_dim=16, anomaly_threshold_std_dev=2.0, random_state=42)
    
    logger.info(f"Training VAE on {X_train_normal.shape[0]} normal samples...")
    vae_detector.train(X_train_normal, epochs=10, batch_size=32) # Reduced epochs for quick test

    # Predict
    logger.info(f"Predicting on test data of shape {X_test.shape}...")
    predictions, scores = vae_detector.predict(X_test)

    # Evaluate (simple accuracy for illustration)
    accuracy = np.mean(predictions == y_test_true)
    logger.info(f"Test predictions: {predictions}")
    # logger.info(f"Test scores (MSE): {scores}") # scores are MSEs
    logger.info(f"Ground truth: {y_test_true}")
    logger.info(f"Accuracy on test set: {accuracy:.4f}")

    model_save_path_prefix = "data/ml_models_test/vae_subclassed_test_model" 
    model_dir = os.path.dirname(model_save_path_prefix)
    if not os.path.exists(model_dir):
        os.makedirs(model_dir, exist_ok=True)
        
    logger.info(f"Saving model to prefix: {model_save_path_prefix}")
    vae_detector.save(model_save_path_prefix)

    logger.info("Loading model...")
    loaded_vae_detector = VAEAnomalyDetector.load(model_save_path_prefix)

    logger.info(f"Predicting with loaded model on test data of shape {X_test.shape}...")
    loaded_predictions, loaded_scores = loaded_vae_detector.predict(X_test)
    loaded_accuracy = np.mean(loaded_predictions == y_test_true)
    logger.info(f"Loaded model accuracy on test set: {loaded_accuracy:.4f}")

    assert np.array_equal(predictions, loaded_predictions), "Predictions from original and loaded model do not match."
    assert np.allclose(scores, loaded_scores), "Scores from original and loaded model do not match."
    logger.info("VAE Anomaly Detector example (with subclassed VAE) finished successfully.")

    # Test with missing columns
    X_test_missing_col = X_test.drop(columns=['feature1'])
    try:
        logger.info("Testing prediction with missing column (should fail)...")
        loaded_vae_detector.predict(X_test_missing_col)
    except ValueError as e:
        logger.info(f"Correctly failed with ValueError: {e}")

    # Test with extra columns (should be handled by reordering)
    X_test_extra_col = X_test.copy()
    X_test_extra_col['extra_feature'] = np.random.rand(X_test_extra_col.shape[0])
    logger.info("Testing prediction with extra column (should be handled)...")
    preds_extra, _ = loaded_vae_detector.predict(X_test_extra_col)
    assert np.array_equal(preds_extra, loaded_predictions), "Predictions with extra column failed."
    logger.info("Prediction with extra column successful.")
