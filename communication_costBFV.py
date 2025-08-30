
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress ALL TensorFlow logs (INFO, WARN, ERROR)
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'  # Disable oneDNN warnings
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'  # Disable GPU detection (if you don't need it)
#import keras
import tensorflow
from tensorflow.keras import layers
from flwr_datasets import FederatedDataset
from flwr_datasets.partitioner import IidPartitioner
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Flatten, Dense, Conv2D, MaxPooling2D
from tensorflow.keras.layers import Dropout, BatchNormalization, LeakyReLU
from tensorflow.keras.callbacks import Callback, EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from tensorflow.keras import optimizers
from tensorflow.keras.utils import to_categorical
import time
import tenseal as ts
import numpy as np
from util import *
import sys

tensorflow.config.set_visible_devices([], 'GPU')  # Hide GPUs from TensorFlow
# Global context - client has full access to keys
context = ts.context(
    ts.SCHEME_TYPE.BFV,
    poly_modulus_degree=16384,    # Polynomial modulus degree
    plain_modulus=65537        # Plain text modulus (must be prime)
)
# settings to get reproducible results, still the results are not entirely reproducible.
SEED = 42
os.environ['PYTHONHASHSEED']=str(SEED)
random.seed(SEED)
np.random.seed(SEED)
tensorflow.random.set_seed(SEED)
# Generate galois keys for rotations/shifts if needed
context.generate_galois_keys()

# Make TensorFlow log less verbose
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"


def load_model(learning_rate: float = 0.001):
    loss = 'categorical_crossentropy'
    optim = optimizers.Nadam(learning_rate=0.001, beta_1=0.9, beta_2=0.999, epsilon=1e-07, name='Nadam')
    net = Sequential(name='cnn_8k')

    net.add(
        Conv2D(
            filters=32,
            kernel_size=(3,3),
            input_shape=(28, 28, 1),
            name='conv2d_1'
        )
    )
     
    net.add(LeakyReLU(name='leaky_relu_1'))
    net.add(BatchNormalization(name='batchnorm_1'))
    net.add(MaxPooling2D(pool_size=(2,2), name='max_pool_1'))

    net.add(
        Conv2D(
            filters=14,
            kernel_size=(3,3),
            name='conv2d_2'
        )
    )
    net.add(LeakyReLU(name='leaky_relu_2'))
    net.add(BatchNormalization(name='batchnorm_2'))
    net.add(MaxPooling2D(pool_size=(2,2), name='max_pool_2'))

    net.add(Flatten(name='flatten_layer'))
    net.add(Dropout(0.2, name='dropout_1'))
    net.add(Dense(10, activation='softmax', name='dense_out'))  
    
    
    net.compile(
        loss=loss,
        optimizer=optim,
        metrics=['accuracy']
    )
    
    #net.summary()
    return net


fds = None  # Cache FederatedDataset


def load_data(partition_id, num_partitions):
    # Download and partition dataset
    # Only initialize `FederatedDataset` once
    global fds
    if fds is None:
        partitioner = IidPartitioner(num_partitions=num_partitions)
        fds = FederatedDataset(
            dataset="mnist",
            partitioners={"train": partitioner},
        )
    partition = fds.load_partition(partition_id, "train")
    partition.set_format("numpy")

    # Divide data on each node: 80% train, 20% test
    def preprocess_data(X, normalize=True):
        X = X.astype('float32')
        if normalize:
            X /= 255.
        return X.reshape(*X.shape, 1)
    partition = partition.train_test_split(test_size=0.2)
    x_train = preprocess_data(partition["train"]["image"])  # Changed from "img" to "image"
    y_train = partition["train"]["label"]
    x_test = preprocess_data(partition["test"]["image"])    # Changed from "img" to "image"
    y_test = partition["test"]["label"]
    y_train = to_categorical(y_train, num_classes=10)
    y_test = to_categorical(y_test, num_classes=10)

    return x_train, y_train, x_test, y_test


early_stopping = EarlyStopping(
    monitor='val_accuracy',
    mode='max',
    min_delta=0.00005,
    #baseline=0.98,
    patience=5,
    restore_best_weights=True,
    verbose=1
)

lr_scheduler = ReduceLROnPlateau(
    monitor='val_accuracy',
    patience=4,
    factor=0.5,
    min_lr=1e-6,
    verbose=1
)

callbacks = [
    early_stopping,
    lr_scheduler,
]

context = ts.context(
    ts.SCHEME_TYPE.BFV,
    poly_modulus_degree=16384,    # Polynomial modulus degree
    plain_modulus=65537        # Plain text modulus (must be prime)
)
# settings to get reproducible results, still the results are not entirely reproducible.
SEED = 42
os.environ['PYTHONHASHSEED']=str(SEED)
random.seed(SEED)
np.random.seed(SEED)
tensorflow.random.set_seed(SEED)
# Generate galois keys for rotations/shifts if needed
context.generate_galois_keys()

model = load_model()
params= model.get_weights()

flat_params = np.concatenate([p.flatten() for p in params])

sizes = [100, 1000, 2000, 4000, 6000, len(flat_params)]

results= []
for size in sizes:
    flat_params_copy = flat_params[:size].copy()
   
    
    enc_chunks = [ts.bfv_vector(context, flat_params_copy[i:i+chunk_size]) 
                    for i in range(0, len(flat_params_copy), chunk_size)]
    
    
    print("Length of encrypted chunks:", len(enc_chunks))
    # Encrypt the parameters
    serialized_params = [enc_arr.serialize() for enc_arr in enc_chunks]

    soma =0
    for chunk in serialized_params:
        soma += sys.getsizeof(chunk)
    print("Total serialized size:", soma, "bytes")
   
    results.append({
        'size':size,
        'total_serialized_size':soma,
         'total_serialized_size_kb': soma / 1024,
        'total_serialized_size_mb': soma / (1024**2)
    }),
    

with open('communication_cost_BFV.txt', 'w') as f:
    f.write("Size,Total Bytes,KB,MB\n")
    for result in results:
        f.write(f"{result['size']},{result['total_serialized_size']},{result['total_serialized_size_kb']:.2f},{result['total_serialized_size_mb']:.2f}\n")