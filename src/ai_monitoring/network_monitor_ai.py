# networking_tester/networking_tester/ai_monitoring/network_monitor_ai.py
# Script de Python
# Desarrollado para networking_tester

import pandas as pd
from sklearn.ensemble import IsolationForest # Ejemplo para detección de anomalías
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import numpy as np
# from tensorflow.keras.models import load_model # Si usas un modelo pre-entrenado de Keras

# Para cargar/guardar modelos con scikit-learn
import joblib
import os

class NetworkAIMonitor:
    def __init__(self, model_path=None):
        self.model = None
        self.scaler = None # Para normalizar/estandarizar datos
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
            # También deberías cargar el scaler si se guardó
            scaler_path = model_path.replace(".joblib", "_scaler.joblib")
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)

    def preprocess_data(self, packet_features_list):
        """
        Convierte una lista de diccionarios de características de paquetes en un DataFrame
        y lo preprocesa (ej. normalización, selección de características).
        Args:
            packet_features_list (list): Lista de diccionarios, donde cada dict
                                         representa las características de un paquete/flujo.
        Returns:
            pd.DataFrame: DataFrame preprocesado listo para el modelo.
        """
        if not packet_features_list:
            return None

        df = pd.DataFrame(packet_features_list)
        
        # Ejemplo de selección de características y manejo de datos faltantes/categóricos
        # Esto es MUY dependiente de tus datos y el modelo que uses.
        # Aquí asumimos que las características ya son numéricas o se han convertido.
        # Por ejemplo, podrías tener 'packet_length', 'inter_arrival_time', 'protocol_type' (codificado)

        # Ejemplo de características numéricas
        # features_to_use = ['packet_length', 'delta_time', 'src_port', 'dst_port']
        # df_selected = df[features_to_use].copy()
        # df_selected.fillna(df_selected.mean(), inplace=True) # Imputación simple

        # ESTO ES UN EJEMPLO MUY BÁSICO. Necesitarás un preprocesamiento más robusto.
        # Supongamos que tenemos características relevantes ya extraídas y numéricas.
        df.fillna(0, inplace=True) # Ejemplo muy crudo de imputación

        # Normalización/Estandarización (importante para muchos modelos de ML)
        # Si ya tienes un scaler entrenado (ej. al cargar el modelo), úsalo.
        # Si estás entrenando, ajusta y transforma.
        numeric_cols = df.select_dtypes(include=np.number).columns
        if not numeric_cols.empty:
            if self.scaler is None:
                self.scaler = StandardScaler()
                df[numeric_cols] = self.scaler.fit_transform(df[numeric_cols])
            else:
                df[numeric_cols] = self.scaler.transform(df[numeric_cols])
        
        return df


    def train_anomaly_detector(self, normal_traffic_features_list, model_save_path="data/models/anomaly_detector.joblib"):
        """
        Entrena un modelo de detección de anomalías (ej. Isolation Forest).
        Args:
            normal_traffic_features_list (list): Lista de características de tráfico normal.
            model_save_path (str): Ruta para guardar el modelo entrenado.
        """
        df_normal = self.preprocess_data(normal_traffic_features_list)
        if df_normal is None or df_normal.empty:
            print("No hay datos suficientes para entrenar.")
            return

        print("Entrenando detector de anomalías...")
        # Ajusta los parámetros del modelo según sea necesario
        self.model = IsolationForest(contamination='auto', random_state=42) # Contamination es una estimación de la proporción de outliers
        self.model.fit(df_normal)
        print("Entrenamiento completado.")

        # Guardar el modelo y el scaler
        model_dir = os.path.dirname(model_save_path)
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
        joblib.dump(self.model, model_save_path)
        print(f"Modelo guardado en: {model_save_path}")
        if self.scaler:
            scaler_save_path = model_save_path.replace(".joblib", "_scaler.joblib")
            joblib.dump(self.scaler, scaler_save_path)
            print(f"Scaler guardado en: {scaler_save_path}")


    def predict_anomalies(self, traffic_features_list):
        """
        Predice si las muestras de tráfico son anomalías.
        Args:
            traffic_features_list (list): Lista de características del tráfico a evaluar.
        Returns:
            list: Lista de predicciones (-1 para anomalía, 1 para normal).
        """
        if self.model is None:
            print("El modelo no está cargado o entrenado.")
            return None
        if not traffic_features_list:
            print("No hay datos para predecir.")
            return []

        df_traffic = self.preprocess_data(traffic_features_list)
        if df_traffic is None or df_traffic.empty:
            print("No se pudieron preprocesar los datos para predicción.")
            return []
            
        predictions = self.model.predict(df_traffic)
        # scores = self.model.decision_function(df_traffic) # Puntuación de anomalía
        return predictions #, scores

    def load_model(self, model_path):
        """Carga un modelo previamente entrenado."""
        try:
            self.model = joblib.load(model_path)
            print(f"Modelo cargado desde: {model_path}")
            scaler_path = model_path.replace(".joblib", "_scaler.joblib")
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                print(f"Scaler cargado desde: {scaler_path}")
        except FileNotFoundError:
            print(f"Error: Archivo de modelo no encontrado en {model_path}")
        except Exception as e:
            print(f"Error al cargar el modelo: {e}")

    def interpret_results(self, packets_data, predictions):
        """
        Interpreta los resultados de la IA y muestra información relevante.
        Args:
            packets_data (list): Lista original de datos de paquetes/flujos.
            predictions (list): Lista de predicciones del modelo.
        """
        print("\n--- Resultados del Monitoreo con IA ---")
        anomalies_found = 0
        for i, pred in enumerate(predictions):
            original_info = packets_data[i].get('summary', f"Paquete/Flujo {i+1}") # Asume que 'summary' está en los datos
            if pred == -1: # Anomalía detectada
                anomalies_found += 1
                print(f"[ANOMALÍA DETECTADA] Concerniente a: {original_info}")
                # Aquí podrías añadir más detalles sobre por qué podría ser una anomalía,
                # basándote en las características del paquete/flujo `packets_data[i]`.
                # Por ejemplo, si es un intento de conexión a muchos puertos, o un tamaño de paquete inusual.

                # Ejemplo de cómo podrías relacionarlo con los requerimientos del taller:
                # if packets_data[i].get('is_suspicious_port_scan', False):
                #     print("  Razón Potencial: Posible escaneo de puertos (Seguridad).")
                # if packets_data[i].get('high_latency_indicator') > X:
                #     print("  Razón Potencial: Alta latencia (Desempeño).")
                # if packets_data[i].get('qos_priority_mismatch', False):
                #     print("  Razón Potencial: Discrepancia en QoS.")

        if anomalies_found == 0:
            print("No se detectaron anomalías en el tráfico analizado.")
        else:
            print(f"Total de anomalías detectadas: {anomalies_found}")

        # Aquí también podrías mostrar estadísticas generales de QoS, desempeño, etc.
        # Por ejemplo, si tu IA clasifica el tráfico y tienes contadores:
        # print("\nDistribución del Tráfico (QoS):")
        # print(f"  Tráfico de Video: {self.stats.get('video_bytes', 0)} bytes")
        # print(f"  Tráfico de Voz: {self.stats.get('voice_bytes', 0)} bytes")
        # print("\nDesempeño Promedio:")
        # print(f"  Latencia Media (si se mide): {self.stats.get('avg_latency', 'N/A')} ms")

# Ejemplo de cómo se podría usar (integrado en main.py o un flujo de trabajo):
# 1. Capturar tramas (Punto 5)
# 2. Extraer características relevantes de cada trama/flujo.
#    Ej. características = [{'packet_length': len(pkt), 'protocol': pkt[IP].proto if pkt.haslayer(IP) else 0, ...}, ...]
#
# # Para entrenar (hacerlo una vez con datos etiquetados o "normales"):
# # ai_monitor = NetworkAIMonitor()
# # normal_traffic_data = [...] # Cargar o generar datos de tráfico normal
# # ai_monitor.train_anomaly_detector(normal_traffic_data, "data/models/my_anomaly_model.joblib")
#
# # Para monitorear:
# # ai_monitor_loaded = NetworkAIMonitor(model_path="data/models/my_anomaly_model.joblib")
# # current_traffic_data = [...] # Características del tráfico actual
# # if ai_monitor_loaded.model:
# #    predictions = ai_monitor_loaded.predict_anomalies(current_traffic_data)
# #    if predictions:
# #        ai_monitor_loaded.interpret_results(current_traffic_data_original_info, predictions)