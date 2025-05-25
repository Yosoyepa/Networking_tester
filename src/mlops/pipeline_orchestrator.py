"""
Main script to orchestrate the MLOps pipeline (training, evaluation, registration).

This script could:
1. Define pipeline stages.
2. Trigger stages sequentially or based on conditions.
3. Manage artifacts and parameters between stages.
4. Integrate with CI/CD systems or schedulers.

For a more advanced setup, tools like Apache Airflow, Kubeflow Pipelines, or MLflow Projects
would be used. This is a simplified, script-based orchestrator.
"""
import logging
import argparse
import os
import sys # Ensure sys is imported
from pathlib import Path # Add Path import

# Add project root to sys.path if not already present
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Print sys.path for debugging
print(f"DEBUG: sys.path = {sys.path}", file=sys.stderr)


import subprocess # For calling other scripts
import datetime
import json
import mlflow
# from src.utils.config_manager import load_app_settings, load_train_config # Corrected import
from src.utils.config_manager import ConfigManager # Import ConfigManager class

# from src.utils.logging_config import setup_logging # Example

logger = logging.getLogger(__name__)

# Script paths (ensure these are correct and consistently used)
ORCHESTRATOR_DIR = os.path.dirname(os.path.abspath(__file__))
TRAIN_SCRIPT_PATH = os.path.join(ORCHESTRATOR_DIR, "train_model.py")
EVALUATE_SCRIPT_PATH = os.path.join(ORCHESTRATOR_DIR, "evaluate_model.py")
REGISTER_SCRIPT_PATH = os.path.join(ORCHESTRATOR_DIR, "register_model.py")
AI_MONITORING_DIR = os.path.abspath(os.path.join(ORCHESTRATOR_DIR, "..", "ai_monitoring"))
PERFORMANCE_ANALYZER_SCRIPT_PATH = os.path.join(AI_MONITORING_DIR, "performance_analyzer_ml.py")

class MLOpsPipelineOrchestrator:
    def __init__(self, config_path: str):
        # Load app settings from the default 'config/settings.yaml' using ConfigManager
        ConfigManager.load_config() # This loads 'config/settings.yaml' by default
        self.app_settings = ConfigManager._config # Access the loaded dictionary

        # Load the specific training/pipeline configuration JSON file
        project_root = Path(__file__).resolve().parent.parent.parent
        
        # Ensure config_path is absolute or resolve it relative to project_root
        abs_config_path = Path(config_path)
        if not abs_config_path.is_absolute():
            abs_config_path = project_root / config_path
        
        if not abs_config_path.exists():
            logger.error(f"Training configuration file not found: {abs_config_path}")
            raise FileNotFoundError(f"Training configuration file not found: {abs_config_path}")

        try:
            with open(abs_config_path, 'r') as f:
                self.train_config = json.load(f)
            logger.info(f"Successfully loaded training configuration from: {abs_config_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from training configuration file {abs_config_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading training configuration file {abs_config_path}: {e}")
            raise

        self.config_path = str(abs_config_path) # Store the absolute path to the original config file

        # Centralized MLflow Setup
        mlflow_settings = self.app_settings.get('mlflow', {})
        tracking_uri = mlflow_settings.get('tracking_uri')
        
        if tracking_uri:
            # MLflow resolves relative paths from CWD.
            # If CWD is 'networking_tester/' and tracking_uri is 'sqlite:///../mlruns.db',
            # it points to 'c:/Users/juanc/Documents/Proyectos Personales/mlruns.db'.
            # For simplicity, ensure CWD is project root when running, or use absolute paths in settings.yaml
            mlflow.set_tracking_uri(tracking_uri)
            logger.info(f"MLflow tracking URI set to: {tracking_uri}")
        else:
            # Fallback if not specified in settings.yaml
            project_root_for_mlflow = os.path.abspath(os.path.join(ORCHESTRATOR_DIR, "..", ".."))
            default_tracking_uri_abs = f"sqlite:///{os.path.join(project_root_for_mlflow, 'mlruns.db')}" # Ensure this points to the DB file itself
            logger.warning(
                f"MLflow tracking URI not found in settings.yaml. Using default: {default_tracking_uri_abs}"
            )
            mlflow.set_tracking_uri(default_tracking_uri_abs)

        self.experiment_name = mlflow_settings.get('experiment_name', 'DefaultNetworkingExperiment')
        experiment = mlflow.get_experiment_by_name(self.experiment_name)
        if experiment is None:
            logger.info(f"Experiment '{self.experiment_name}' not found. Creating new experiment.")
            mlflow.create_experiment(self.experiment_name)
        mlflow.set_experiment(self.experiment_name)
        logger.info(f"MLflow experiment set to: {self.experiment_name}")

    def run_pipeline(self):
        _model_name = self.train_config.get('model_name', 'UnknownModel')
        _model_version = self.train_config.get('model_version', '0.0.0')
        _run_timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        run_name = f"{_model_name}_v{_model_version}_{_run_timestamp}"
        
        logger.info(f"Attempting to start MLflow run: {run_name} for experiment: {self.experiment_name}")

        with mlflow.start_run(run_name=run_name) as run:
            mlflow_run_id = run.info.run_id
            logger.info(f"MLflow run ID: {mlflow_run_id} started successfully.")

            if os.path.exists(self.config_path):
                mlflow.log_artifact(self.config_path, artifact_path="config")
                logger.info(f"Logged original config artifact: {self.config_path}")
            else:
                logger.warning(f"Original config path '{self.config_path}' not found. Cannot log as artifact.")

            project_root = os.path.abspath(os.path.join(ORCHESTRATOR_DIR, "..", ".."))
            run_artifacts_dir_relative_to_project = os.path.join("data", "mlops_artifacts", _model_name, f"{_model_version.replace('.', '_')}_{_run_timestamp}")
            run_artifacts_dir_abs = os.path.join(project_root, run_artifacts_dir_relative_to_project)
            os.makedirs(run_artifacts_dir_abs, exist_ok=True)
            logger.info(f"Run artifacts will be stored in: {run_artifacts_dir_abs}")
            mlflow.log_param("run_artifacts_directory_abs", run_artifacts_dir_abs)

            run_specific_train_config = self.train_config.copy()
            trained_model_filename = f"{_model_name}_{_model_version}.joblib"
            
            run_specific_train_config["output_model_path"] = os.path.join(run_artifacts_dir_relative_to_project, trained_model_filename)
            
            evaluation_results_filename = "evaluation_metrics.json"
            run_specific_train_config["output_metrics_path"] = os.path.join(run_artifacts_dir_relative_to_project, evaluation_results_filename)

            # Resolve data paths to be absolute, assuming they are relative to project root in the config
            training_data_key = "training_data_source" # As per recent config changes
            evaluation_data_key = "evaluation_data_source"

            # Ensure project_root is defined correctly before this block
            # project_root = os.path.abspath(os.path.join(ORCHESTRATOR_DIR, "..", "..")) # Should be already defined

            if training_data_key in run_specific_train_config and run_specific_train_config[training_data_key]:
                current_training_path = run_specific_train_config[training_data_key]
                if not os.path.isabs(current_training_path):
                    abs_training_path = os.path.join(project_root, current_training_path)
                    run_specific_train_config[training_data_key] = abs_training_path
                    logger.info(f"Resolved relative {training_data_key} to absolute: {abs_training_path}")
                else:
                    logger.info(f"{training_data_key} is already absolute: {current_training_path}")
            
            if evaluation_data_key in run_specific_train_config and run_specific_train_config[evaluation_data_key]:
                current_eval_path = run_specific_train_config[evaluation_data_key]
                if not os.path.isabs(current_eval_path):
                    abs_eval_path = os.path.join(project_root, current_eval_path)
                    run_specific_train_config[evaluation_data_key] = abs_eval_path
                    logger.info(f"Resolved relative {evaluation_data_key} to absolute: {abs_eval_path}")
                else:
                    logger.info(f"{evaluation_data_key} is already absolute: {current_eval_path}")
            elif training_data_key in run_specific_train_config and run_specific_train_config[training_data_key]: # Fallback for evaluation data
                run_specific_train_config[evaluation_data_key] = run_specific_train_config[training_data_key]
                logger.info(f"Set {evaluation_data_key} to the same as {training_data_key}: {run_specific_train_config[training_data_key]}")


            run_specific_train_config_path_abs = os.path.join(run_artifacts_dir_abs, "training_run_config.json")
            with open(run_specific_train_config_path_abs, 'w') as f:
                json.dump(run_specific_train_config, f, indent=4)
            logger.info(f"Created run-specific training config: {run_specific_train_config_path_abs}")
            mlflow.log_artifact(run_specific_train_config_path_abs, artifact_path="config")

            # These paths are now absolute, derived from the relative paths in run_specific_train_config
            trained_model_path_abs = os.path.join(project_root, run_specific_train_config["output_model_path"])
            evaluation_results_path_abs = os.path.join(project_root, run_specific_train_config["output_metrics_path"])
            
            model_type_for_eval = run_specific_train_config.get("model_type", "gmm")

            # --- Stage 1: Train Model ---
            train_command = [
                TRAIN_SCRIPT_PATH,
                "--config", run_specific_train_config_path_abs
            ]
            if not self._run_pipeline_step(train_command, "Model Training", mlflow_run_id=mlflow_run_id, project_root=project_root):
                self._fail_pipeline("Model Training", mlflow_run_id)
                return

            # --- Stage 2: Evaluate Model ---
            evaluate_command = [
                EVALUATE_SCRIPT_PATH,
                "--config", run_specific_train_config_path_abs,
                "--model_type", model_type_for_eval # Corrected: use underscore
            ]
            if not self._run_pipeline_step(evaluate_command, "Model Evaluation", mlflow_run_id=mlflow_run_id, project_root=project_root):
                self._fail_pipeline("Model Evaluation", mlflow_run_id)
                return

            # --- Stage 3: Performance Analysis ---
            performance_analysis_output_dir_abs = os.path.join(run_artifacts_dir_abs, "performance_analysis_results")
            os.makedirs(performance_analysis_output_dir_abs, exist_ok=True)
            
            performance_analyzer_input_path = run_specific_train_config.get(evaluation_data_key) # Use resolved absolute path
            if not performance_analyzer_input_path or not os.path.exists(performance_analyzer_input_path):
                 logger.warning(f"Performance analyzer input path not found or invalid: {performance_analyzer_input_path}. Skipping performance analysis.")
                 mlflow.set_tag("performance_analysis_status", "skipped")
            else:
                logger.info(f"Performance analyzer will use input data from: {performance_analyzer_input_path}")
                performance_analyzer_command = [
                    PERFORMANCE_ANALYZER_SCRIPT_PATH,
                    "--features-input-path", performance_analyzer_input_path,
                    "--output-dir", performance_analysis_output_dir_abs,
                    "--mlflow-active-run-id", mlflow_run_id
                ]
                if not self._run_pipeline_step(performance_analyzer_command, "Performance Analysis", mlflow_run_id=mlflow_run_id, project_root=project_root):
                    logger.warning("Performance analysis step failed. Continuing pipeline, but marking with warning.")
                    mlflow.set_tag("performance_analysis_status", "failed")
                else:
                    logger.info("Performance analysis step completed successfully.")
                    mlflow.set_tag("performance_analysis_status", "success")
            
            # --- Stage 4: Register Model ---
            model_metadata_path_abs = os.path.join(run_artifacts_dir_abs, "model_metadata.json")
            try:
                eval_metrics = {}
                if os.path.exists(evaluation_results_path_abs):
                    with open(evaluation_results_path_abs, 'r') as f:
                        eval_metrics = json.load(f)
                
                model_metadata_content = {
                    "source_training_config_original": self.config_path, # Original config path
                    "source_training_config_run_specific_abs": run_specific_train_config_path_abs,
                    "evaluation_metrics": eval_metrics,
                    "trained_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "model_artifact_path_in_run_abs": trained_model_path_abs,
                    "pipeline_run_id": mlflow_run_id 
                }
                with open(model_metadata_path_abs, 'w') as f:
                    json.dump(model_metadata_content, f, indent=4)
                logger.info(f"Created model metadata file: {model_metadata_path_abs}")
                mlflow.log_artifact(model_metadata_path_abs, artifact_path="run_metadata")

            except Exception as e:
                logger.error(f"Failed to create or log model metadata: {e}", exc_info=True)
                self._fail_pipeline("Metadata Creation", mlflow_run_id)
                return

            register_command = [
                REGISTER_SCRIPT_PATH,
                "--config", run_specific_train_config_path_abs, 
                "--model_type", model_type_for_eval # Corrected: use underscore
            ]
            if not self._run_pipeline_step(register_command, "Model Registration", mlflow_run_id=mlflow_run_id, project_root=project_root):
                self._fail_pipeline("Model Registration", mlflow_run_id)
                return

            logger.info(f"MLOps pipeline orchestration finished successfully for {_model_name} v{_model_version}.")
            logger.info(f"MLflow Run ID: {mlflow_run_id}. Artifacts logged to MLflow and stored locally in: {run_artifacts_dir_abs}")
            mlflow.set_tag("pipeline_status", "success")
            mlflow.end_run() 
            return mlflow_run_id

    def _fail_pipeline(self, failure_stage: str, mlflow_run_id: str):
        logger.error(f"{failure_stage} failed. Aborting pipeline.")
        # Ensure we are modifying the correct run, especially if __init__ starts a run that fails before run_pipeline
        current_run = mlflow.active_run()
        if current_run and current_run.info.run_id == mlflow_run_id:
            mlflow.set_tag("pipeline_status", "failed")
            mlflow.set_tag("failure_stage", failure_stage)
            mlflow.end_run(status="FAILED")
        else:
            logger.warning(f"No active MLflow run or mismatched run ID (expected {mlflow_run_id}, active {current_run.info.run_id if current_run else 'None'}) to mark as failed for stage: {failure_stage}")


    def _run_pipeline_step(self, command: list, step_name: str, mlflow_run_id: str = None, project_root: str = None):
        logger.info(f"Starting step: {step_name} with command: {' '.join(command)}") # Use single quotes for join
        try:
            if project_root is None:
                project_root = os.path.abspath(os.path.join(ORCHESTRATOR_DIR, "..", ".."))
            
            env = os.environ.copy()
            current_pythonpath = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = f"{project_root}{os.pathsep}{current_pythonpath}" # Ensure project root is in PYTHONPATH
            
            if mlflow_run_id:
                env["MLFLOW_RUN_ID"] = mlflow_run_id
                logger.info(f"Propagating MLFLOW_RUN_ID: {mlflow_run_id} to step {step_name}")

            process_command = [sys.executable] + command # command[0] is script path, should be absolute
            
            process = subprocess.run(process_command, 
                                     capture_output=True, 
                                     text=True, 
                                     check=False, 
                                     cwd=project_root, # Run from project root
                                     env=env)
            
            if process.returncode != 0:
                logger.error(f"Step {step_name} failed. Return code: {process.returncode}")
                logger.error(f"Stdout:\\n{process.stdout}") # Use \\n for newline
                logger.error(f"Stderr:\\n{process.stderr}") # Use \\n for newline
                current_run = mlflow.active_run()
                if current_run and current_run.info.run_id == mlflow_run_id:
                    # Log stdout/stderr to MLflow as artifacts for easier debugging
                    stdout_file = os.path.join(project_root, "stdout.txt") # Create in CWD (project_root)
                    stderr_file = os.path.join(project_root, "stderr.txt")
                    with open(stdout_file, "w") as f_stdout: f_stdout.write(process.stdout)
                    mlflow.log_artifact(stdout_file, artifact_path=f"step_logs/{step_name.replace(' ', '_')}")
                    with open(stderr_file, "w") as f_stderr: f_stderr.write(process.stderr)
                    mlflow.log_artifact(stderr_file, artifact_path=f"step_logs/{step_name.replace(' ', '_')}")
                    os.remove(stdout_file) # Clean up temp files
                    os.remove(stderr_file)
                return False

            logger.info(f"Step {step_name} output:\\n{process.stdout}") # Use \\n for newline
            if process.stderr:
                logger.warning(f"Step {step_name} stderr (non-fatal):\\n{process.stderr}") # Use \\n for newline
            logger.info(f"Step {step_name} completed successfully.")
            return True
        except Exception as e: # Catch any other exception during subprocess handling
            logger.error(f"An unexpected error occurred while running step {step_name}: {e}", exc_info=True)
            return False

# Comment out old procedural functions
# def load_pipeline_config(config_path: str) -> dict:
# ... (rest of the old function) ...

# def orchestrate_ml_pipeline(pipeline_config_path: str):
# ... (rest of the old function) ...

def main():
    parser = argparse.ArgumentParser(description="MLOps Pipeline Orchestrator")
    parser.add_argument("--config", type=str, required=True, 
                        help="Path to the pipeline/training configuration JSON file (e.g., config/mlops_train_config_gmm_test.json)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', # Use single quotes
                        handlers=[logging.StreamHandler(sys.stdout)])

    logger.info(f"Initializing MLOpsPipelineOrchestrator with config: {args.config}")
    
    project_root = os.path.abspath(os.path.join(ORCHESTRATOR_DIR, "..", ".."))
    abs_config_path = args.config
    if not os.path.isabs(abs_config_path):
        abs_config_path = os.path.join(project_root, abs_config_path)
    
    if not os.path.exists(abs_config_path):
        logger.error(f"Configuration file not found: {abs_config_path}. Please provide a valid path relative to the project root or an absolute path.")
        sys.exit(1)

    try:
        orchestrator = MLOpsPipelineOrchestrator(config_path=abs_config_path)
        orchestrator.run_pipeline()
    except Exception as e:
        logger.error(f"Pipeline orchestration failed with an unhandled exception: {e}", exc_info=True)
        current_run = mlflow.active_run()
        if current_run: # Attempt to end run if one is active
             mlflow.end_run(status="FAILED")
        sys.exit(1)

if __name__ == "__main__": # Corrected: Use double quotes
    main()
