\
import csv
import numpy as np
import os

# Configuration
N_SAMPLES = 2000
N_FEATURES = 5
ANOMALY_FRACTION = 0.08  # 8% anomalies
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "ml_training_data")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "realistic_evaluation_data.csv")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Generate normal data
# Normal data will be centered around a mean for each feature
mean_normal = np.random.rand(N_FEATURES) * 10  # Random means between 0 and 10
covariance_normal = np.diag(np.random.rand(N_FEATURES) * 2 + 0.5) # Random variances

n_normal_samples = int(N_SAMPLES * (1 - ANOMALY_FRACTION))
normal_data = np.random.multivariate_normal(mean_normal, covariance_normal, n_normal_samples)

# Generate anomalous data
# Anomalies will be further from the normal data's mean or have different characteristics
n_anomalies = N_SAMPLES - n_normal_samples
anomalous_data = []

for _ in range(n_anomalies):
    # Create different types of anomalies
    anomaly_type = np.random.choice(['shift', 'scale', 'outlier_cluster'])
    
    if anomaly_type == 'shift':
        # Shifted mean
        shift_factor = (np.random.rand(N_FEATURES) - 0.5) * 20 # Shift by -10 to +10
        anomaly = np.random.multivariate_normal(mean_normal + shift_factor, covariance_normal, 1)
    elif anomaly_type == 'scale':
        # Different covariance (scaled)
        scale_factor = np.random.uniform(3, 6) # Scale variance up
        anomaly = np.random.multivariate_normal(mean_normal, covariance_normal * scale_factor, 1)
    else: # outlier_cluster
        # Data points from a different, distant cluster
        mean_anomaly_cluster = mean_normal + (np.random.rand(N_FEATURES) * 30 -15) # Further away
        covariance_anomaly_cluster = np.diag(np.random.rand(N_FEATURES) * 1 + 0.2) # Tighter cluster
        anomaly = np.random.multivariate_normal(mean_anomaly_cluster, covariance_anomaly_cluster, 1)
    anomalous_data.append(anomaly[0])

anomalous_data = np.array(anomalous_data)

# Combine data and add labels
data = np.vstack((normal_data, anomalous_data))
labels = np.array([0] * n_normal_samples + [1] * n_anomalies)

# Shuffle the data
permutation = np.random.permutation(N_SAMPLES)
data = data[permutation]
labels = labels[permutation]

# Write to CSV
header = [f"feature{i+1}" for i in range(N_FEATURES)] + ["is_anomaly"]

with open(OUTPUT_FILE, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(header)
    for i in range(N_SAMPLES):
        writer.writerow(list(data[i]) + [labels[i]])

print(f"Successfully generated {N_SAMPLES} samples ({n_anomalies} anomalies) into {OUTPUT_FILE}")

# Example of how the data looks (first 5 rows)
print("\\nFirst 5 rows of the generated data:")
with open(OUTPUT_FILE, 'r') as f:
    for i, line in enumerate(f):
        if i < 6: # header + 5 rows
            print(line.strip())
        else:
            break
