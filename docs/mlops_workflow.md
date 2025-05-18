# MLOps Workflow for Network Anomaly Detection

## 1. Overview

This document outlines the MLOps pipeline implemented for the Networking Tester project. The primary purpose of this pipeline is to automate the training, evaluation, and registration of machine learning models for tasks such as network anomaly detection. It ensures reproducibility, manages model artifacts, and provides a structured way to iterate on models.

## 2. Components

The MLOps pipeline consists of several key Python scripts, configuration files, and a model registry:

*   **`src/mlops/pipeline_orchestrator.py`**:
    *   The main entry point for the MLOps pipeline.
    *   Orchestrates the execution of training, evaluation, and registration stages.
    *   Manages run-specific artifact directories.
    *   Handles pipeline configuration.

*   **`src/mlops/train_model.py`**:
    *   Responsible for training the machine learning model.
    *   Loads training data and a training configuration file (JSON).
    *   Performs feature selection and preprocessing.
    *   Trains the specified model (e.g., `IsolationForest`).
    *   Saves the trained model artifact (e.g., using `joblib`).

*   **`src/mlops/evaluate_model.py`**:
    *   Evaluates a trained model.
    *   Loads the model artifact and evaluation data (CSV).
    *   Uses a feature configuration (typically the training config) for consistency.
    *   Performs predictions.
    *   Calculates evaluation metrics (e.g., classification report, confusion matrix if labels are available).
    *   Saves the metrics to a JSON file.

*   **`src/mlops/register_model.py`**:
    *   Registers the trained and evaluated model into the model registry.
    *   Takes the model artifact path, model name, version, and metadata as input.
    *   Uses `ModelRegistryClient` to update the central model registry.

*   **`src/ai_monitoring/model_registry_client.py`**:
    *   A client utility to interact with the file-based model registry (`data/models/model_registry.json`).
    *   Provides methods to list models, get model versions, retrieve model details, and register new models/versions.

*   **Configuration Files**:
    *   **Pipeline/Training Configuration (e.g., `config/mlops_train_config_sample.json`)**: A JSON file that defines parameters for the entire pipeline run, including model name, version, data sources, feature columns, and model-specific hyperparameters. The orchestrator uses this to generate a run-specific training config.
    *   **Run-Specific Training Configuration (e.g., `data/mlops_artifacts/.../training_run_config.json`)**: A copy of the main training config, modified by the orchestrator with run-specific paths (e.g., for the output model artifact). This is passed to the training and evaluation scripts.

*   **Artifacts**:
    *   **Run-Specific Directory (e.g., `data/mlops_artifacts/<model_name>/<model_version_timestamp>/`)**: A directory created for each pipeline run to store all its outputs.
    *   **Trained Model (e.g., `*.joblib`)**: The serialized model file.
    *   **Evaluation Metrics (e.g., `evaluation_metrics.json`)**: JSON file containing performance metrics.
    *   **Model Metadata (e.g., `model_metadata.json`)**: JSON file containing information about the run, including paths to configs, metrics, and the trained model.
    *   **Model Registry (`data/models/model_registry.json`)**: A central JSON file tracking all registered models, their versions, paths, and metadata.

## 3. Workflow Steps

The MLOps pipeline executes in the following sequence, orchestrated by `pipeline_orchestrator.py`:

1.  **Initialization**:
    *   The orchestrator is invoked with a path to a main pipeline configuration file.
    *   It loads this configuration.
    *   A unique run-specific artifact directory is created under `data/mlops_artifacts/`.

2.  **Training Configuration Preparation**:
    *   The orchestrator creates a run-specific training configuration JSON file within the artifact directory. This involves:
        *   Copying the main pipeline configuration.
        *   Updating paths (e.g., `output_model_path`) to point within the run-specific artifact directory.
    *   This run-specific config is saved.

3.  **Model Training (`train_model.py`)**:
    *   The orchestrator invokes `train_model.py` as a subprocess.
    *   The training script:
        *   Loads the run-specific training configuration.
        *   Loads the training data (e.g., CSV) as specified in the config.
        *   Performs feature selection/engineering based on `feature_columns` in the config.
        *   Initializes and trains the model (e.g., `IsolationForest`) using hyperparameters from the config.
        *   Saves the trained model to the `output_model_path` specified in its config (within the run's artifact directory).

4.  **Model Evaluation (`evaluate_model.py`)**:
    *   The orchestrator invokes `evaluate_model.py` as a subprocess.
    *   The evaluation script:
        *   Loads the trained model artifact (path provided by the orchestrator).
        *   Loads the evaluation data (path from the main pipeline config).
        *   Loads the run-specific training configuration to ensure consistent feature columns are used.
        *   Performs predictions on the evaluation data.
        *   If true labels are present in the evaluation data, it calculates metrics like `classification_report` and `confusion_matrix`.
        *   Saves these metrics to an `evaluation_metrics.json` file in the run's artifact directory.

5.  **Model Metadata Creation**:
    *   The orchestrator gathers information about the run, including:
        *   Path to the run-specific training configuration.
        *   The evaluation metrics loaded from `evaluation_metrics.json`.
        *   Timestamp of training.
        *   Path to the model artifact within the run directory.
        *   A unique run ID.
    *   This information is saved to `model_metadata.json` in the run's artifact directory.

6.  **Model Registration (`register_model.py`)**:
    *   The orchestrator invokes `register_model.py` as a subprocess.
    *   The registration script:
        *   Takes the path to the trained model artifact, model name, model version, and the path to `model_metadata.json`.
        *   Initializes `ModelRegistryClient`.
        *   Calls the `register_model` method of the client, passing the model details and loaded metadata.
        *   The `ModelRegistryClient` updates (or creates) `data/models/model_registry.json` with the new model's version information, storing paths relative to the project root.

7.  **Completion**:
    *   The orchestrator logs the successful completion and the location of the run artifacts.

## 4. Directory Structure for MLOps

Key directories involved in the MLOps process:

*   **`src/mlops/`**: Contains the core pipeline scripts (`pipeline_orchestrator.py`, `train_model.py`, `evaluate_model.py`, `register_model.py`).
*   **`src/ai_monitoring/model_registry_client.py`**: Location of the model registry client.
*   **`config/`**: Intended for storing main pipeline and training configuration files (e.g., `mlops_train_config_sample.json`).
*   **`data/ml_training_data/`**: Stores sample or actual data used for training and evaluation (e.g., `sample_training_data.csv`).
*   **`data/mlops_artifacts/`**: Root directory for all pipeline run artifacts. Each run creates a subdirectory: `<model_name>/<model_version_timestamp>/`.
*   **`data/models/`**:
    *   **`model_registry.json`**: The central manifest file for all registered models.

## 5. How to Run the Pipeline

To execute the MLOps pipeline:

1.  **Ensure Dependencies**: Make sure all Python packages listed in `requirements.txt` are installed (e.g., `pandas`, `scikit-learn`, `joblib`).
2.  **Prepare Configuration**:
    *   Create or verify your main pipeline/training configuration JSON file (e.g., `config/mlops_train_config_sample.json`).
    *   Ensure data paths (`data_source`, `evaluation_data_source`) and other parameters are correctly set.
3.  **Run the Orchestrator**:
    *   Navigate to the project root directory (`networking_tester`) in your terminal.
    *   Execute the `pipeline_orchestrator.py` script, providing the path to your configuration file:

    ```powershell
    python src\mlops\pipeline_orchestrator.py --config config\your_pipeline_config.json
    ```
    For example, using the sample configuration:
    ```powershell
    python src\mlops\pipeline_orchestrator.py --config config\mlops_train_config_sample.json
    ```

4.  **Check Results**:
    *   Monitor the console output for logs from each stage.
    *   After successful execution, find the artifacts in the corresponding `data/mlops_artifacts/<model_name>/<model_version_timestamp>/` directory.
    *   Check `data/models/model_registry.json` to see the newly registered model.

## 6. Future Enhancements

Potential areas for future development of the MLOps pipeline:

*   **Data Validation**: Implement data validation steps (e.g., using Great Expectations) before training and evaluation.
*   **Hyperparameter Tuning**: Integrate automated hyperparameter optimization (e.g., Optuna, Ray Tune).
*   **Experiment Tracking**: Integrate with experiment tracking tools like MLflow or Weights & Biases for more detailed logging of parameters, metrics, and artifacts.
*   **CI/CD Integration**: Automate pipeline execution via CI/CD systems (e.g., GitHub Actions, Jenkins) triggered by code changes or on a schedule.
*   **Model Deployment**: Add steps for deploying registered models to a serving environment.
*   **Monitoring**: Implement monitoring for deployed models to track their performance and detect drift or decay.
*   **Advanced Model Versioning**: Implement more sophisticated versioning strategies.
*   **Scalability**: Refactor for better scalability, potentially using workflow orchestrators like Airflow or Kubeflow Pipelines for more complex pipelines.
*   **Testing**: Add more comprehensive unit and integration tests for the MLOps scripts.

This MLOps workflow provides a solid foundation for managing the lifecycle of machine learning models within the Networking Tester project.
