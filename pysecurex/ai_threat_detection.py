import os
import time
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Tuple
import re

# Machine learning imports
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support

# Deep learning imports
try:
    import tensorflow as tf
    from tensorflow.keras.models import Model, Sequential, load_model
    from tensorflow.keras.layers import Input, Dense, Dropout, LSTM, Conv1D, MaxPooling1D, Flatten
    from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
    from tensorflow.keras.optimizers import Adam
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logging.warning("TensorFlow not available. Deep learning features will be disabled.")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PySecureX.AI_Threat_Detection")


class BaseDetector:
    """Base class for all detectors"""
    
    def __init__(self, name: str = "BaseDetector"):
        self.name = name
        self.model = None
        self.scaler = None
        self.threshold = None
        self.trained = False
        self.feature_names = []
        
    def fit(self, X: np.ndarray, **kwargs) -> None:
        """Train the detector"""
        raise NotImplementedError("Subclasses must implement fit()")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict if samples are anomalies"""
        raise NotImplementedError("Subclasses must implement predict()")
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores for samples"""
        raise NotImplementedError("Subclasses must implement score_samples()")
    
    def save(self, path: str) -> None:
        """Save model to disk"""
        raise NotImplementedError("Subclasses must implement save()")
    
    def load(self, path: str) -> None:
        """Load model from disk"""
        raise NotImplementedError("Subclasses must implement load()")


class IsolationForestDetector(BaseDetector):
    """Anomaly detection using Isolation Forest algorithm"""
    
    def __init__(self, contamination: float = 0.1, random_state: int = 42, n_estimators: int = 100):
        super().__init__(name="IsolationForestDetector")
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=n_estimators,
            n_jobs=-1,
            max_samples="auto",
            bootstrap=True
        )
        self.scaler = StandardScaler()
        
    def fit(self, X: np.ndarray, **kwargs) -> None:
        """Train the detector"""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.trained = True
        logger.info(f"Trained {self.name} on {X.shape[0]} samples with {X.shape[1]} features")
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict if samples are anomalies (1 for normal, -1 for anomaly)"""
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores for samples (lower = more anomalous)"""
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        X_scaled = self.scaler.transform(X)
        return self.model.score_samples(X_scaled)
    
    def save(self, path: str) -> None:
        """Save model to disk"""
        import pickle
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'trained': self.trained,
                'feature_names': self.feature_names
            }, f)
        logger.info(f"Saved {self.name} to {path}")
    
    def load(self, path: str) -> None:
        """Load model from disk"""
        import pickle
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.scaler = data['scaler']
            self.trained = data['trained']
            self.feature_names = data['feature_names']
        logger.info(f"Loaded {self.name} from {path}")


class AutoencoderDetector(BaseDetector):
    """Anomaly detection using an autoencoder neural network"""
    
    def __init__(self, hidden_dims: List[int] = None, activation: str = 'relu', 
                 learning_rate: float = 0.001, epochs: int = 100, batch_size: int = 32,
                 validation_split: float = 0.1, anomaly_threshold: float = 0.95):
        super().__init__(name="AutoencoderDetector")
        
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow is required for AutoencoderDetector")
            
        self.hidden_dims = hidden_dims or [64, 32, 16, 32, 64]
        self.activation = activation
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.batch_size = batch_size
        self.validation_split = validation_split
        self.anomaly_threshold = anomaly_threshold
        self.model = None
        self.reconstruction_errors = []
        self.threshold = None
        self.scaler = MinMaxScaler()
        
    def _build_model(self, input_dim: int) -> None:
        """Build the autoencoder model"""
        # Input layer
        inputs = Input(shape=(input_dim,))
        
        # Encoder
        encoded = inputs
        for dim in self.hidden_dims[:len(self.hidden_dims)//2]:
            encoded = Dense(dim, activation=self.activation)(encoded)
        
        # Bottleneck layer
        bottleneck = Dense(self.hidden_dims[len(self.hidden_dims)//2], activation=self.activation)(encoded)
        
        # Decoder
        decoded = bottleneck
        for dim in self.hidden_dims[len(self.hidden_dims)//2+1:]:
            decoded = Dense(dim, activation=self.activation)(decoded)
        
        # Output layer
        outputs = Dense(input_dim, activation='sigmoid')(decoded)
        
        # Create model
        autoencoder = Model(inputs, outputs)
        autoencoder.compile(optimizer=Adam(learning_rate=self.learning_rate), loss='mse')
        
        self.model = autoencoder
        logger.info(f"Built autoencoder model with architecture: {self.hidden_dims}")
        
    def fit(self, X: np.ndarray, **kwargs) -> None:
        """Train the autoencoder"""
        X_scaled = self.scaler.fit_transform(X)
        
        # Build the model if it doesn't exist
        if self.model is None:
            self._build_model(X.shape[1])
        
        # Early stopping to prevent overfitting
        early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
        
        # Train the model
        self.model.fit(
            X_scaled, X_scaled,
            epochs=self.epochs,
            batch_size=self.batch_size,
            validation_split=self.validation_split,
            callbacks=[early_stopping],
            verbose=kwargs.get('verbose', 0)
        )
        
        # Calculate reconstruction errors on training data
        predictions = self.model.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - predictions, 2), axis=1)
        self.reconstruction_errors = mse
        
        # Set threshold based on percentile of reconstruction errors
        self.threshold = np.percentile(mse, self.anomaly_threshold * 100)
        
        self.trained = True
        logger.info(f"Trained {self.name} on {X.shape[0]} samples with {X.shape[1]} features")
        logger.info(f"Reconstruction error threshold set to {self.threshold}")
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict if samples are anomalies (1 for normal, -1 for anomaly)"""
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        
        scores = self.score_samples(X)
        return np.where(scores > self.threshold, -1, 1)
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores for samples (higher = more anomalous)"""
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - predictions, 2), axis=1)
        return mse
    
    def save(self, path: str) -> None:
        """Save model to disk"""
        if not self.trained:
            raise RuntimeError("Model not trained. Cannot save untrained model.")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Save Keras model
        self.model.save(f"{path}_model.h5")
        
        # Save other attributes
        import pickle
        with open(f"{path}_attributes.pkl", 'wb') as f:
            pickle.dump({
                'threshold': self.threshold,
                'reconstruction_errors': self.reconstruction_errors,
                'scaler': self.scaler,
                'trained': self.trained,
                'feature_names': self.feature_names,
                'hidden_dims': self.hidden_dims,
                'activation': self.activation,
                'anomaly_threshold': self.anomaly_threshold
            }, f)
        
        logger.info(f"Saved {self.name} to {path}")
    
    def load(self, path: str) -> None:
        """Load model from disk"""
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow is required to load an AutoencoderDetector")
        
        # Load Keras model
        self.model = load_model(f"{path}_model.h5")
        
        # Load other attributes
        import pickle
        with open(f"{path}_attributes.pkl", 'rb') as f:
            data = pickle.load(f)
            self.threshold = data['threshold']
            self.reconstruction_errors = data['reconstruction_errors']
            self.scaler = data['scaler']
            self.trained = data['trained']
            self.feature_names = data['feature_names']
            self.hidden_dims = data['hidden_dims']
            self.activation = data['activation']
            self.anomaly_threshold = data['anomaly_threshold']
        
        logger.info(f"Loaded {self.name} from {path}")


class NetworkTrafficDetector:
    """Detect anomalies in network traffic"""
    
    def __init__(self, model_type: str = "autoencoder", model_path: str = None):
        self.model_type = model_type.lower()
        self.model_path = model_path
        
        if self.model_type == "autoencoder" and TF_AVAILABLE:
            self.detector = AutoencoderDetector()
        elif self.model_type == "isolationforest":
            self.detector = IsolationForestDetector()
        else:
            self.detector = IsolationForestDetector()
            logger.warning(f"Model type '{model_type}' not recognized or not available. Defaulting to IsolationForest.")
        
        # Try to load the model if path is provided
        if self.model_path and os.path.exists(self.model_path):
            try:
                self.detector.load(self.model_path)
            except Exception as e:
                logger.error(f"Failed to load model from {self.model_path}: {e}")
        
        self.feature_extractors = {
            'packet_size_stats': self._extract_packet_size_stats,
            'time_stats': self._extract_time_stats,
            'protocol_stats': self._extract_protocol_stats,
            'connection_stats': self._extract_connection_stats
        }
    
    def _extract_packet_size_stats(self, packets: List[Dict]) -> Dict:
        """Extract packet size statistics"""
        sizes = [p.get('size', 0) for p in packets]
        return {
            'mean_size': np.mean(sizes) if sizes else 0,
            'std_size': np.std(sizes) if sizes else 0,
            'min_size': np.min(sizes) if sizes else 0,
            'max_size': np.max(sizes) if sizes else 0,
            'median_size': np.median(sizes) if sizes else 0
        }
    
    def _extract_time_stats(self, packets: List[Dict]) -> Dict:
        """Extract time-based statistics"""
        timestamps = [p.get('timestamp', 0) for p in packets]
        if len(timestamps) < 2:
            return {
                'mean_interval': 0,
                'std_interval': 0,
                'min_interval': 0,
                'max_interval': 0,
                'packet_rate': 0
            }
        
        intervals = np.diff(timestamps)
        total_time = timestamps[-1] - timestamps[0]
        
        return {
            'mean_interval': np.mean(intervals),
            'std_interval': np.std(intervals),
            'min_interval': np.min(intervals),
            'max_interval': np.max(intervals),
            'packet_rate': len(packets) / total_time if total_time > 0 else 0
        }
    
    def _extract_protocol_stats(self, packets: List[Dict]) -> Dict:
        """Extract protocol statistics"""
        protocols = [p.get('protocol', 'unknown') for p in packets]
        protocol_counts = {}
        
        for protocol in set(protocols):
            protocol_counts[f'protocol_{protocol}'] = protocols.count(protocol) / len(protocols)
        
        return protocol_counts
    
    def _extract_connection_stats(self, packets: List[Dict]) -> Dict:
        """Extract connection statistics"""
        src_ips = [p.get('src_ip', 'unknown') for p in packets]
        dst_ips = [p.get('dst_ip', 'unknown') for p in packets]
    
        # Calculate unique IPs and ports
        unique_src_ips = len(set(src_ips))
        unique_dst_ips = len(set(dst_ips))
        
        # Calculate connection pairs
        connection_pairs = set([(p.get('src_ip', 'unknown'), p.get('dst_ip', 'unknown'), 
                                p.get('src_port', 0), p.get('dst_port', 0)) 
                                for p in packets])
        
        # Calculate ports
        src_ports = [p.get('src_port', 0) for p in packets]
        dst_ports = [p.get('dst_port', 0) for p in packets]
        unique_src_ports = len(set(src_ports))
        unique_dst_ports = len(set(dst_ports))
        
        return {
            'unique_src_ips': unique_src_ips,
            'unique_dst_ips': unique_dst_ips,
            'unique_connection_pairs': len(connection_pairs),
            'unique_src_ports': unique_src_ports,
            'unique_dst_ports': unique_dst_ports,
            'src_ip_entropy': self._calculate_entropy(src_ips),
            'dst_ip_entropy': self._calculate_entropy(dst_ips),
            'src_port_entropy': self._calculate_entropy(src_ports),
            'dst_port_entropy': self._calculate_entropy(dst_ports),
            'connection_ratio': len(connection_pairs) / len(packets) if packets else 0
        }

    def _calculate_entropy(self, items: List) -> float:
        """Calculate Shannon entropy of a list of items"""
        if not items:
            return 0.0
        
        # Count occurrences of each item
        counts = {}
        for item in items:
            counts[item] = counts.get(item, 0) + 1
        
        # Calculate probabilities
        total = len(items)
        probabilities = [count / total for count in counts.values()]
        
        # Calculate entropy
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        return entropy

    def extract_features(self, packets: List[Dict], include_extractors: List[str] = None) -> Dict:
        """Extract features from network packets"""
        if not packets:
            logger.warning("No packets provided for feature extraction")
            return {}
        
        # Use all extractors if none specified
        if include_extractors is None:
            include_extractors = list(self.feature_extractors.keys())
        
        # Validate extractors
        valid_extractors = [ext for ext in include_extractors if ext in self.feature_extractors]
        if len(valid_extractors) != len(include_extractors):
            logger.warning(f"Some extractors are not valid: {set(include_extractors) - set(valid_extractors)}")
        
        # Extract features
        features = {}
        for extractor_name in valid_extractors:
            extractor_fn = self.feature_extractors[extractor_name]
            features.update(extractor_fn(packets))
        
        return features

    def process_pcap(self, pcap_path: str) -> pd.DataFrame:
        """Process a PCAP file and extract features"""
        try:
            import pyshark
            cap = pyshark.FileCapture(pcap_path)
            packets = []
            
            for packet in cap:
                try:
                    # Extract basic packet info
                    packet_info = {
                        'timestamp': float(packet.sniff_timestamp),
                        'size': int(packet.length),
                        'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'unknown'
                    }
                    
                    # Extract IP info if available
                    if hasattr(packet, 'ip'):
                        packet_info.update({
                            'src_ip': packet.ip.src,
                            'dst_ip': packet.ip.dst,
                        })
                    
                    # Extract port info if available
                    if hasattr(packet, 'tcp'):
                        packet_info.update({
                            'src_port': int(packet.tcp.srcport),
                            'dst_port': int(packet.tcp.dstport)
                        })
                    elif hasattr(packet, 'udp'):
                        packet_info.update({
                            'src_port': int(packet.udp.srcport),
                            'dst_port': int(packet.udp.dstport)
                        })
                    else:
                        packet_info.update({
                            'src_port': 0,
                            'dst_port': 0
                        })
                    
                    packets.append(packet_info)
                except Exception as e:
                    logger.debug(f"Error processing packet: {e}")
                    continue
            
            # Group packets into time windows
            window_size = 60  # seconds
            windows = {}
            
            for packet in packets:
                timestamp = packet['timestamp']
                window_id = int(timestamp // window_size)
                if window_id not in windows:
                    windows[window_id] = []
                windows[window_id].append(packet)
            
            # Extract features for each window
            feature_rows = []
            for window_id, window_packets in windows.items():
                features = self.extract_features(window_packets)
                features['window_id'] = window_id
                features['window_start_time'] = window_id * window_size
                features['packet_count'] = len(window_packets)
                feature_rows.append(features)
            
            # Create DataFrame
            return pd.DataFrame(feature_rows)
        
        except ImportError:
            logger.error("pyshark not installed. Cannot process PCAP files.")
            return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error processing PCAP file {pcap_path}: {e}")
            return pd.DataFrame()

    def detect_anomalies(self, features: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
        """Detect anomalies in network traffic features"""
        if features.empty:
            logger.warning("No features provided for anomaly detection")
            return features, np.array([])
        
        # Drop non-numeric columns
        numeric_features = features.select_dtypes(include=np.number).copy()
        
        # Drop any columns with NaN values
        numeric_features = numeric_features.dropna(axis=1)
        
        # Save column names for future reference
        feature_names = numeric_features.columns.tolist()
        self.detector.feature_names = feature_names
        
        # Check if model needs to be trained
        if not self.detector.trained:
            logger.info("Training detector on provided features")
            self.detector.fit(numeric_features.values)
            
            # Save model if path is provided
            if self.model_path:
                try:
                    self.detector.save(self.model_path)
                except Exception as e:
                    logger.error(f"Failed to save model to {self.model_path}: {e}")
        
        # Predict anomalies
        anomaly_scores = self.detector.score_samples(numeric_features.values)
        anomaly_predictions = self.detector.predict(numeric_features.values)
        
        # Add results to DataFrame
        features['anomaly_score'] = anomaly_scores
        features['is_anomaly'] = anomaly_predictions == -1
        
        return features, anomaly_predictions


class FileAnalyzer:
    """Analyze files for malicious content"""
    
    def __init__(self, model_type: str = "isolationforest", model_path: str = None):
        self.model_type = model_type.lower()
        self.model_path = model_path
        
        if self.model_type == "autoencoder" and TF_AVAILABLE:
            self.detector = AutoencoderDetector()
        else:
            self.detector = IsolationForestDetector()
        
        # Try to load the model if path is provided
        if self.model_path and os.path.exists(self.model_path):
            try:
                self.detector.load(self.model_path)
            except Exception as e:
                logger.error(f"Failed to load model from {self.model_path}: {e}")
    
    def extract_file_features(self, file_path: str) -> Dict:
        """Extract features from a file"""
        features = {}
        
        try:
            # Basic file statistics
            file_stats = os.stat(file_path)
            features.update({
                'file_size': file_stats.st_size,
                'creation_time': file_stats.st_ctime,
                'modification_time': file_stats.st_mtime,
                'access_time': file_stats.st_atime,
            })
            
            # File type and extension
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()
            features['file_extension'] = file_ext
            
            # Read file content for binary analysis
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Byte frequency analysis
            byte_counts = [0] * 256
            for byte in content:
                byte_counts[byte] += 1
            
            # Calculate entropy
            total_bytes = len(content)
            if total_bytes > 0:
                byte_probabilities = [count / total_bytes for count in byte_counts]
                entropy = -sum(p * np.log2(p) for p in byte_probabilities if p > 0)
                features['entropy'] = entropy
            else:
                features['entropy'] = 0
            
            # Calculate byte frequency features
            for i in range(0, 256, 16):  # Group bytes to reduce feature count
                group_sum = sum(byte_counts[i:i+16])
                features[f'byte_group_{i//16}'] = group_sum / total_bytes if total_bytes > 0 else 0
            
            # PE file specific features
            if file_ext in ['.exe', '.dll', '.sys']:
                try:
                    import pefile
                    pe = pefile.PE(file_path)
                    
                    # Number of sections
                    features['num_sections'] = len(pe.sections)
                    
                    # Entry point
                    features['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    
                    # Import/export info
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        features['num_imports'] = sum(len(module.imports) for module in pe.DIRECTORY_ENTRY_IMPORT)
                    else:
                        features['num_imports'] = 0
                    
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                        features['num_exports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
                    else:
                        features['num_exports'] = 0
                    
                    # Section info
                    section_entropies = []
                    for section in pe.sections:
                        section_data = section.get_data()
                        if section_data:
                            counts = {}
                            for byte in section_data:
                                counts[byte] = counts.get(byte, 0) + 1
                            total = len(section_data)
                            probabilities = [count / total for count in counts.values()]
                            section_entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
                            section_entropies.append(section_entropy)
                    
                    if section_entropies:
                        features['avg_section_entropy'] = np.mean(section_entropies)
                        features['max_section_entropy'] = np.max(section_entropies)
                    else:
                        features['avg_section_entropy'] = 0
                        features['max_section_entropy'] = 0
                    
                except ImportError:
                    logger.warning("pefile not installed. Cannot analyze PE files.")
                except Exception as e:
                    logger.debug(f"Error analyzing PE file {file_path}: {e}")
            
            return features
        
        except Exception as e:
            logger.error(f"Error extracting features from file {file_path}: {e}")
            return {'error': str(e)}
    
    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a file for malicious content"""
        # Extract features
        features = self.extract_file_features(file_path)
        
        if 'error' in features:
            return {'status': 'error', 'error': features['error']}
        
        # Convert to DataFrame
        features_df = pd.DataFrame([features])
        
        # Remove non-numeric columns for anomaly detection
        numeric_features = features_df.select_dtypes(include=np.number)
        
        # If model is not trained, we can't predict
        if not self.detector.trained:
            return {
                'status': 'unknown',
                'message': 'Model not trained. Cannot analyze file.',
                'features': features
            }
        
        # Ensure feature alignment with trained model
        if self.detector.feature_names:
            # Add missing columns with zeros
            for feature in self.detector.feature_names:
                if feature not in numeric_features.columns:
                    numeric_features[feature] = 0
            
            # Select only columns that were used during training
            numeric_features = numeric_features[self.detector.feature_names]
        
        # Predict anomaly
        try:
            anomaly_score = self.detector.score_samples(numeric_features.values)[0]
            is_anomaly = self.detector.predict(numeric_features.values)[0] == -1
            
            result = {
                'status': 'malicious' if is_anomaly else 'benign',
                'anomaly_score': float(anomaly_score),
                'features': features,
                'confidence': float(1.0 - (anomaly_score / self.detector.threshold)) if hasattr(self.detector, 'threshold') and self.detector.threshold else 0.0
            }
            
            return result
        
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'features': features
            }


class LogAnalyzer:
    """Analyze system logs for intrusion detection"""
    
    def __init__(self, model_type: str = "isolationforest", model_path: str = None):
        self.model_type = model_type.lower()
        self.model_path = model_path
        
        if self.model_type == "autoencoder" and TF_AVAILABLE:
            self.detector = AutoencoderDetector()
        else:
            self.detector = IsolationForestDetector()
        
        # Try to load the model if path is provided
        if self.model_path and os.path.exists(self.model_path):
            try:
                self.detector.load(self.model_path)
            except Exception as e:
                logger.error(f"Failed to load model from {self.model_path}: {e}")
        
        # Regular expressions for log parsing
        self.log_patterns = {
            'ssh': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)',
            'sudo': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sudo\[(?P<pid>\d+)\]:\s+(?P<message>.*)',
            'auth': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+auth:\s+(?P<message>.*)',
            'firewall': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+kernel:\s+(?P<message>.*)',
            'generic': r'(?P<timestamp>\S+\s+\S+)\s+(?P<message>.*)'
        }
        
        # Patterns for known attack signatures
        self.attack_signatures = {
            'brute_force': [
                r'authentication failure',
                r'failed password',
                r'invalid user',
                r'Failed password for .* from'
            ],
            'privilege_escalation': [
                r'COMMAND=.*?/bin/(bash|sh|nc|netcat)',
                r'COMMAND=.*?(chmod|chown).+?777',
                r'user NOT in sudoers',
                r'NOPASSWD'
            ],
            'data_exfiltration': [
                r'ESTABLISHED.*?tcp.*?(1337|4444|8888|9999)',
                r'outbound connection to',
                r'unusual traffic spike',
                r'large file transfer'
            ]
        }
    
    def parse_log_line(self, line: str, log_type: str = None) -> Dict:
        """Parse a log line using appropriate regex pattern"""
        # Try specific log type if provided
        if log_type and log_type in self.log_patterns:
            pattern = self.log_patterns[log_type]
            match = re.search(pattern, line)
            if match:
                return match.groupdict()
        
        # Try all patterns if log type not provided or specific pattern didn't match
        for log_type, pattern in self.log_patterns.items():
            match = re.search(pattern, line)
            if match:
                result = match.groupdict()
                result['log_type'] = log_type
                return result
        
        # Use generic pattern as fallback
        match = re.search(self.log_patterns['generic'], line)
        if match:
            result = match.groupdict()
            result['log_type'] = 'unknown'
            return result
        
        # Return minimal info if nothing matches
        return {
            'timestamp': datetime.now().strftime('%b %d %H:%M:%S'),
            'message': line,
            'log_type': 'unknown'
        }
    
    def extract_log_features(self, logs: List[Dict]) -> Dict:
        """Extract features from parsed log entries"""
        if not logs:
            return {}
        
        # Time-based features
        timestamps = []
        for log in logs:
            try:
                if 'timestamp' in log:
                    # Add current year since most syslog entries don't include it
                    current_year = datetime.now().year
                    log_time = datetime.strptime(f"{current_year} {log['timestamp']}", "%Y %b %d %H:%M:%S")
                    timestamps.append(log_time)
            except Exception:
                continue
        
        # Skip time features if no valid timestamps
        time_features = {}
        if timestamps:
            # Sort timestamps
            timestamps.sort()
            
            # Calculate time intervals
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                          for i in range(len(timestamps)-1)]
            
            time_features = {
                'log_count': len(timestamps),
                'timespan_seconds': (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) > 1 else 0,
                'mean_interval': np.mean(intervals) if intervals else 0,
                'std_interval': np.std(intervals) if intervals else 0,
                'min_interval': min(intervals) if intervals else 0,
                'max_interval': max(intervals) if intervals else 0
            }
        else:
            time_features = {
                'log_count': len(logs),
                'timespan_seconds': 0,
                'mean_interval': 0,
                'std_interval': 0,
                'min_interval': 0,
                'max_interval': 0
            }
        
        # Log type distribution
        log_types = [log.get('log_type', 'unknown') for log in logs]
        log_type_counts = {}
        for log_type in set(log_types):
            log_type_counts[f'log_type_{log_type}'] = log_types.count(log_type) / len(log_types)
        
        # Attack signature detection
        message_texts = [log.get('message', '') for log in logs]
        signature_matches = {}
        
        for attack_type, patterns in self.attack_signatures.items():
            match_count = 0
            for message in message_texts:
                if any(re.search(pattern, message, re.IGNORECASE) for pattern in patterns):
                    match_count += 1
            signature_matches[f'signature_{attack_type}'] = match_count / len(logs)
        
        # User and IP statistics
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        user_pattern = r'user (\w+)'
        
        # Extract IPs and users
        ips = []
        users = []
        
        for message in message_texts:
            ip_matches = re.findall(ip_pattern, message)
            ips.extend(ip_matches)
            
            user_matches = re.findall(user_pattern, message, re.IGNORECASE)
            users.extend(user_matches)
        
        # Calculate statistics
        ip_stats = {
            'unique_ips': len(set(ips)),
            'ip_ratio': len(set(ips)) / len(ips) if ips else 0,
            'ip_entropy': self._calculate_entropy(ips)
        }
        
        user_stats = {
            'unique_users': len(set(users)),
            'user_ratio': len(set(users)) / len(users) if users else 0,
            'user_entropy': self._calculate_entropy(users)
        }
        
        # Combine all features
        features = {}
        features.update(time_features)
        features.update(log_type_counts)
        features.update(signature_matches)
        features.update(ip_stats)
        features.update(user_stats)
        
        return features
    
    def _calculate_entropy(self, items: List) -> float:
        """Calculate Shannon entropy of a list of items"""
        if not items:
            return 0.0
        
        # Count occurrences of each item
        counts = {}
        for item in items:
            counts[item] = counts.get(item, 0) + 1
        
        # Calculate probabilities
        total = len(items)
        probabilities = [count / total for count in counts.values()]
        
        # Calculate entropy
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        return entropy
    
    def analyze_logs(self, log_file_path: str, log_type: str = None, window_size: int = 100) -> pd.DataFrame:
        """Analyze logs for anomalies using sliding window approach"""
        # Read log file
        try:
            with open(log_file_path, 'r') as f:
                log_lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading log file {log_file_path}: {e}")
            return pd.DataFrame()
        
        # Parse log lines
        parsed_logs = []
        for line in log_lines:
            try:
                parsed_log = self.parse_log_line(line.strip(), log_type)
                parsed_logs.append(parsed_log)
            except Exception as e:
                logger.debug(f"Error parsing log line: {e}")
                continue
        
        if not parsed_logs:
            logger.warning(f"No logs could be parsed from {log_file_path}")
            return pd.DataFrame()
        
        # Process logs in sliding windows
        feature_rows = []
        for i in range(0, len(parsed_logs), window_size // 2):
            window_logs = parsed_logs[i:i+window_size]
            if len(window_logs) < window_size // 4:
                continue  # Skip small windows
                
            features = self.extract_log_features(window_logs)
            features['window_start'] = i
            features['window_end'] = i + len(window_logs)
            feature_rows.append(features)
        
        # Create DataFrame
        features_df = pd.DataFrame(feature_rows)
        
        if features_df.empty:
            logger.warning("No features extracted from logs")
            return features_df
        
        # Detect anomalies if model is trained
        if self.detector.trained:
            try:
                # Drop non-numeric columns
                numeric_features = features_df.select_dtypes(include=np.number)
                
                # Predict anomalies
                anomaly_scores = self.detector.score_samples(numeric_features.values)
                anomaly_predictions = self.detector.predict(numeric_features.values)
                
                # Add results to DataFrame
                features_df['anomaly_score'] = anomaly_scores
                features_df['is_anomaly'] = anomaly_predictions == -1
                
            except Exception as e:
                logger.error(f"Error detecting anomalies in logs: {e}")
        else:
            logger.warning("Model not trained. Anomaly detection skipped.")
        
        return features_df
    
    def train_on_logs(self, log_file_path: str, log_type: str = None, window_size: int = 100) -> bool:
        """Train the model on log data"""
        features_df = self.analyze_logs(log_file_path, log_type, window_size)
        
        if features_df.empty:
            logger.warning("No features extracted from logs for training")
            return False
        
        try:
            # Drop non-numeric columns
            numeric_features = features_df.select_dtypes(include=np.number)
            
            # Drop columns with NaN values
            numeric_features = numeric_features.dropna(axis=1)
            
            # Save feature names
            self.detector.feature_names = numeric_features.columns.tolist()
            
            # Train the model
            self.detector.fit(numeric_features.values)
            
            # Save model if path is provided
            if self.model_path:
                try:
                    self.detector.save(self.model_path)
                except Exception as e:
                    logger.error(f"Failed to save model to {self.model_path}: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training model on logs: {e}")
            return False


class ThreatDetectionSystem:
    """Main class that integrates all threat detection capabilities"""
    
    def __init__(self):
        self.network_detector = NetworkTrafficDetector()
        self.file_analyzer = FileAnalyzer()
        self.log_analyzer = LogAnalyzer()
        
        # Directory for saving models and results
        self.model_dir = os.path.join(os.path.expanduser("~"), ".pysecurex", "models")
        self.results_dir = os.path.join(os.path.expanduser("~"), ".pysecurex", "results")
        
        # Create directories if they don't exist
        os.makedirs(self.model_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)
    
    def scan_network(self, pcap_path: str = None, live_interface: str = None, duration: int = 60) -> Dict:
        """Scan network traffic for anomalies"""
        # Check if we have a PCAP file or need to capture live traffic
        if pcap_path and os.path.exists(pcap_path):
            logger.info(f"Analyzing PCAP file: {pcap_path}")
            features_df = self.network_detector.process_pcap(pcap_path)
        elif live_interface:
            # Capture live traffic
            temp_pcap = os.path.join(self.results_dir, f"capture_{int(time.time())}.pcap")
            logger.info(f"Capturing traffic on interface {live_interface} for {duration} seconds")
            
            try:
                import subprocess
                cmd = ["tcpdump", "-i", live_interface, "-w", temp_pcap]
                proc = subprocess.Popen(cmd)
                time.sleep(duration)
                proc.terminate()
                proc.wait()
                
                # Process the capture file
                features_df = self.network_detector.process_pcap(temp_pcap)
                
                # Clean up temporary file
                os.remove(temp_pcap)
            except Exception as e:
                logger.error(f"Error capturing live traffic: {e}")
                return {"status": "error", "message": str(e)}
        else:
            logger.error("Either PCAP file or network interface must be provided")
            return {"status": "error", "message": "No input provided"}
        
        if features_df.empty:
            return {"status": "error", "message": "No features extracted from traffic"}
        
        # Detect anomalies
        results_df, predictions = self.network_detector.detect_anomalies(features_df)
        
        # Save results
        timestamp = int(time.time())
        results_path = os.path.join(self.results_dir, f"network_scan_{timestamp}.csv")
        results_df.to_csv(results_path, index=False)
        
        # Summarize results
        anomaly_count = (predictions == -1).sum()
        total_windows = len(predictions)
        
        return {
            "status": "completed",
            "timestamp": timestamp,
            "total_windows": total_windows,
            "anomaly_count": int(anomaly_count),
            "anomaly_percentage": float(anomaly_count / total_windows * 100) if total_windows > 0 else 0,
            "results_path": results_path,
            "top_anomalies": results_df[results_df["is_anomaly"]].sort_values("anomaly_score").head(5).to_dict("records") if "is_anomaly" in results_df.columns else []
        }
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan a file for malicious content"""
        if not os.path.exists(file_path):
            return {"status": "error", "message": f"File not found: {file_path}"}
        
        logger.info(f"Analyzing file: {file_path}")
        result = self.file_analyzer.analyze_file(file_path)
        
        # Add timestamp
        result["timestamp"] = int(time.time())
        
        # Save result
        result_path = os.path.join(self.results_dir, f"file_scan_{result['timestamp']}.json")
        with open(result_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        result["result_path"] = result_path
        return result
    def scan_directory(self, directory_path: str, recursive: bool = False) -> Dict:
        """Scan all files in a directory for malicious content"""
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            return {"status": "error", "message": f"Directory not found: {directory_path}"}
        
        logger.info(f"Scanning directory: {directory_path}")
        
        # Get list of files to scan
        files_to_scan = []
        if recursive:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    files_to_scan.append(os.path.join(root, file))
        else:
            for entry in os.listdir(directory_path):
                full_path = os.path.join(directory_path, entry)
                if os.path.isfile(full_path):
                    files_to_scan.append(full_path)
        
        # Scan each file
        results = []
        for file_path in files_to_scan:
            try:
                result = self.scan_file(file_path)
                # Only keep minimal info for summary
                summary = {
                    "file_path": file_path,
                    "status": result.get("status", "unknown"),
                    "anomaly_score": result.get("anomaly_score", 0),
                    "confidence": result.get("confidence", 0)
                }
                results.append(summary)
            except Exception as e:
                logger.error(f"Error scanning file {file_path}: {e}")
                results.append({
                    "file_path": file_path,
                    "status": "error",
                    "message": str(e)
                })
        
        # Summarize results
        malicious_count = sum(1 for r in results if r.get("status") == "malicious")
        error_count = sum(1 for r in results if r.get("status") == "error")
        
        summary = {
            "status": "completed",
            "timestamp": int(time.time()),
            "total_files": len(results),
            "malicious_files": malicious_count,
            "clean_files": len(results) - malicious_count - error_count,
            "error_files": error_count,
            "malicious_percentage": (malicious_count / len(results) * 100) if results else 0,
            "results": results
        }
        
        # Save summary
        summary_path = os.path.join(self.results_dir, f"directory_scan_{summary['timestamp']}.json")
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        summary["result_path"] = summary_path
        return summary
    
    def analyze_logs(self, log_file_path: str, log_type: str = None) -> Dict:
        """Analyze system logs for security threats"""
        if not os.path.exists(log_file_path):
            return {"status": "error", "message": f"Log file not found: {log_file_path}"}
        
        logger.info(f"Analyzing logs: {log_file_path}")
        
        # Process logs
        results_df = self.log_analyzer.analyze_logs(log_file_path, log_type)
        
        if results_df.empty:
            return {"status": "error", "message": "No results from log analysis"}
        
        # Save results
        timestamp = int(time.time())
        results_path = os.path.join(self.results_dir, f"log_analysis_{timestamp}.csv")
        results_df.to_csv(results_path, index=False)
        
        # Summarize results
        anomaly_count = results_df["is_anomaly"].sum() if "is_anomaly" in results_df.columns else 0
        total_windows = len(results_df)
        
        return {
            "status": "completed",
            "timestamp": timestamp,
            "total_windows": total_windows,
            "anomaly_count": int(anomaly_count),
            "anomaly_percentage": float(anomaly_count / total_windows * 100) if total_windows > 0 else 0,
            "results_path": results_path,
            "top_anomalies": results_df[results_df["is_anomaly"] == True].sort_values("anomaly_score").head(5).to_dict("records") if "is_anomaly" in results_df.columns else []
        }
    
    def train_models(self, train_data_config: Dict) -> Dict:
        """Train all detector models using provided training data"""
        results = {}
        
        # Train network detector
        if "network" in train_data_config:
            network_config = train_data_config["network"]
            pcap_path = network_config.get("pcap_path")
            
            if pcap_path and os.path.exists(pcap_path):
                logger.info(f"Training network detector on {pcap_path}")
                try:
                    features_df = self.network_detector.process_pcap(pcap_path)
                    if not features_df.empty:
                        # Drop non-numeric columns
                        numeric_features = features_df.select_dtypes(include=np.number)
                        
                        # Train the model
                        model_path = os.path.join(self.model_dir, "network_detector")
                        self.network_detector.detector.fit(numeric_features.values)
                        self.network_detector.detector.feature_names = numeric_features.columns.tolist()
                        self.network_detector.detector.save(model_path)
                        
                        results["network"] = {
                            "status": "success",
                            "samples": len(features_df),
                            "features": len(numeric_features.columns),
                            "model_path": model_path
                        }
                    else:
                        results["network"] = {"status": "error", "message": "No features extracted from PCAP"}
                except Exception as e:
                    logger.error(f"Error training network detector: {e}")
                    results["network"] = {"status": "error", "message": str(e)}
            else:
                results["network"] = {"status": "error", "message": "PCAP file not found"}
        
        # Train file analyzer
        if "files" in train_data_config:
            files_config = train_data_config["files"]
            benign_dir = files_config.get("benign_dir")
            malicious_dir = files_config.get("malicious_dir")
            
            if benign_dir and malicious_dir and os.path.exists(benign_dir) and os.path.exists(malicious_dir):
                logger.info(f"Training file analyzer on {benign_dir} and {malicious_dir}")
                try:
                    # Process benign files
                    benign_features = []
                    for root, _, files in os.walk(benign_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            features = self.file_analyzer.extract_file_features(file_path)
                            if features and "error" not in features:
                                features["is_malicious"] = 0
                                benign_features.append(features)
                    
                    # Process malicious files
                    malicious_features = []
                    for root, _, files in os.walk(malicious_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            features = self.file_analyzer.extract_file_features(file_path)
                            if features and "error" not in features:
                                features["is_malicious"] = 1
                                malicious_features.append(features)
                    
                    # Combine features
                    all_features = benign_features + malicious_features
                    if all_features:
                        # Convert to DataFrame
                        features_df = pd.DataFrame(all_features)
                        
                        # Drop non-numeric columns
                        numeric_features = features_df.select_dtypes(include=np.number)
                        
                        # Train the model
                        model_path = os.path.join(self.model_dir, "file_analyzer")
                        self.file_analyzer.detector.fit(numeric_features.values)
                        self.file_analyzer.detector.feature_names = numeric_features.columns.tolist()
                        self.file_analyzer.detector.save(model_path)
                        
                        results["files"] = {
                            "status": "success",
                            "benign_samples": len(benign_features),
                            "malicious_samples": len(malicious_features),
                            "features": len(numeric_features.columns),
                            "model_path": model_path
                        }
                    else:
                        results["files"] = {"status": "error", "message": "No features extracted from files"}
                except Exception as e:
                    logger.error(f"Error training file analyzer: {e}")
                    results["files"] = {"status": "error", "message": str(e)}
            else:
                results["files"] = {"status": "error", "message": "Benign or malicious directory not found"}
        
        # Train log analyzer
        if "logs" in train_data_config:
            logs_config = train_data_config["logs"]
            log_path = logs_config.get("log_path")
            log_type = logs_config.get("log_type")
            
            if log_path and os.path.exists(log_path):
                logger.info(f"Training log analyzer on {log_path}")
                try:
                    success = self.log_analyzer.train_on_logs(log_path, log_type)
                    if success:
                        model_path = os.path.join(self.model_dir, "log_analyzer")
                        self.log_analyzer.detector.save(model_path)
                        
                        results["logs"] = {
                            "status": "success",
                            "model_path": model_path
                        }
                    else:
                        results["logs"] = {"status": "error", "message": "Failed to train log analyzer"}
                except Exception as e:
                    logger.error(f"Error training log analyzer: {e}")
                    results["logs"] = {"status": "error", "message": str(e)}
            else:
                results["logs"] = {"status": "error", "message": "Log file not found"}
        
        return results
    
    def load_models(self) -> Dict:
        """Load all detector models from default paths"""
        results = {}
        
        # Load network detector
        network_model_path = os.path.join(self.model_dir, "network_detector")
        if os.path.exists(f"{network_model_path}.pkl"):
            try:
                self.network_detector.detector.load(network_model_path)
                results["network"] = {"status": "success", "model_path": network_model_path}
            except Exception as e:
                logger.error(f"Error loading network detector model: {e}")
                results["network"] = {"status": "error", "message": str(e)}
        else:
            results["network"] = {"status": "not_found"}
        
        # Load file analyzer
        file_model_path = os.path.join(self.model_dir, "file_analyzer")
        if os.path.exists(f"{file_model_path}.pkl"):
            try:
                self.file_analyzer.detector.load(file_model_path)
                results["files"] = {"status": "success", "model_path": file_model_path}
            except Exception as e:
                logger.error(f"Error loading file analyzer model: {e}")
                results["files"] = {"status": "error", "message": str(e)}
        else:
            results["files"] = {"status": "not_found"}
        
        # Load log analyzer
        log_model_path = os.path.join(self.model_dir, "log_analyzer")
        if os.path.exists(f"{log_model_path}.pkl"):
            try:
                self.log_analyzer.detector.load(log_model_path)
                results["logs"] = {"status": "success", "model_path": log_model_path}
            except Exception as e:
                logger.error(f"Error loading log analyzer model: {e}")
                results["logs"] = {"status": "error", "message": str(e)}
        else:
            results["logs"] = {"status": "not_found"}
        
        return results
    
    def generate_report(self, results: Dict) -> str:
        """Generate a comprehensive security report"""
        report = []
        
        # Add report header
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report.append(f"# Security Threat Detection Report")
        report.append(f"Generated: {timestamp}\n")
        
        # Add summary
        report.append("## Summary")
        report.append(f"- Scan completed at: {datetime.fromtimestamp(results.get('timestamp', int(time.time()))).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Add specific sections based on scan type
        if "total_windows" in results:  # Network or log scan
            report.append(f"- Total analysis windows: {results.get('total_windows', 0)}")
            report.append(f"- Anomalies detected: {results.get('anomaly_count', 0)} ({results.get('anomaly_percentage', 0):.2f}%)")
            
            # Add details about top anomalies
            if results.get("top_anomalies"):
                report.append("\n## Top Anomalies")
                for i, anomaly in enumerate(results["top_anomalies"], 1):
                    report.append(f"\n### Anomaly {i}")
                    for key, value in anomaly.items():
                        if key not in ["is_anomaly", "window_id"]:
                            report.append(f"- {key}: {value}")
        
        elif "total_files" in results:  # Directory scan
            report.append(f"- Total files scanned: {results.get('total_files', 0)}")
            report.append(f"- Malicious files: {results.get('malicious_files', 0)} ({results.get('malicious_percentage', 0):.2f}%)")
            report.append(f"- Clean files: {results.get('clean_files', 0)}")
            report.append(f"- Files with scan errors: {results.get('error_files', 0)}")
            
            # Add details about malicious files
            malicious_files = [r for r in results.get("results", []) if r.get("status") == "malicious"]
            if malicious_files:
                report.append("\n## Malicious Files")
                for i, file in enumerate(malicious_files, 1):
                    report.append(f"{i}. {file.get('file_path')} (Score: {file.get('anomaly_score', 0):.4f}, Confidence: {file.get('confidence', 0):.2f})")
        
        elif "status" in results and "features" in results:  # Single file scan
            report.append(f"- File status: {results.get('status', 'unknown')}")
            if results.get("status") == "malicious":
                report.append(f"- Anomaly score: {results.get('anomaly_score', 0):.4f}")
                report.append(f"- Confidence: {results.get('confidence', 0):.2f}")
            
            # Add file features
            if results.get("features"):
                report.append("\n## File Features")
                for key, value in results["features"].items():
                    report.append(f"- {key}: {value}")
        
        # Add recommendations based on results
        report.append("\n## Recommendations")
        
        if "anomaly_count" in results and results["anomaly_count"] > 0:
            report.append("- Investigate detected anomalies, particularly those with the highest anomaly scores")
            report.append("- Review network firewall rules and access controls")
            report.append("- Consider updating IDS/IPS signatures based on detected patterns")
        
        if "malicious_files" in results and results["malicious_files"] > 0:
            report.append("- Quarantine or remove identified malicious files")
            report.append("- Scan affected systems with up-to-date antivirus software")
            report.append("- Review file access permissions and user privileges")
        
        # Add footer
        report.append("\n---")
        report.append("This report was generated automatically by PySecureX AI Threat Detection System.")
        report.append("Results should be reviewed by a security professional.")
        
        # Save report to file
        report_path = os.path.join(self.results_dir, f"security_report_{int(time.time())}.md")
        with open(report_path, 'w') as f:
            f.write("\n".join(report))
        
        return "\n".join(report)


