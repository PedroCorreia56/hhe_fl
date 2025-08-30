"""tfexample: A Flower / TensorFlow app."""

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
import exemplo
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






model = load_model()




secret_key = generate_key()

pasta_cipher = exemplo.Pasta3Plain(secret_key, modulus)
print("Creating context for seal??...")
context=exemplo.SEALZpCipher.create_context(mod_degree,modulus, seclevel)
print("Done")
print("Creating client cipher...")
client_cipher=exemplo.Pasta3Seal(secret_key, context)
client_cipher.activate_bsgs(use_bsgs)
client_cipher.add_gk_indices()
client_cipher.create_gk()
print("Client encrypting key...")
client_cipher.encrypt_key(USE_BATCH)



params = model.get_weights()
original_shapes = [layer.shape for layer in params]
original_sizes = [layer.size for layer in params]

flat_params = np.concatenate([w.flatten() for w in params])



# round the flat_params to 5 decimal places
flat_params = np.round(flat_params, 5)

sizes = [100, 1000, 2000, 4000, 6000, len(flat_params)]

print("Model parameters:")
results = []
for size in sizes:

    flat_params_copy = flat_params[:size].copy()


    list_sym_ciphertext = []

    quant_scale = 5 / 127.0  # Scale for int8 quantization
    print("Encrypting parameters...")
    plaintext_int_weights =[]
    plaintext_uint64_weights = []

    deep_nested= False

    clipped = np.clip(flat_params_copy, -MAX_VALUE_WEIGHTS, MAX_VALUE_WEIGHTS)  # Clip to [-max_val, max_val]
    int_weights = np.round(clipped / quant_scale).astype(np.int8)  # Scale to int
    int_weights = int_weights.astype(np.uint64)  # Convert to uint64 for encryption
    list_sym_ciphertext = [ pasta_cipher.encrypt_plain(int_weights[i:i+chunk_size]) 
        for i in range(0, len(int_weights), chunk_size) ]
        


    print("SERIALIZING")
    json_str = json.dumps(list_sym_ciphertext)
    byte_array = json_str.encode('utf-8')
    serialized_params=[byte_array]

    print("SIZE OF Byte array PARAMS:", sys.getsizeof(byte_array))
    print("SIZE OF serialized_params:", sys.getsizeof(serialized_params))



    deserialized_params = json.loads(serialized_params[0].decode('utf-8')) 

    he_ciphertexts = []
    print("HE DECRYPT MODELS")
    start = time.time()
    

    he_ciphertexts = [client_cipher.HE_decrypt(chunk, USE_BATCH) for chunk in deserialized_params]

    end = time.time()
    print(f"HE decryption took {end - start:.2f} seconds")
    serialized_he_ciphertexts = exemplo.serialize_ciphertext_nested(he_ciphertexts)
    soma=0
    soma2=0
    for i, ciphertext in enumerate(serialized_he_ciphertexts):
        print(f"Ciphertext {i} size: {sys.getsizeof(ciphertext)} bytes")
        for j, chunk in enumerate(ciphertext):
            soma2 += sys.getsizeof(chunk)
        soma += sys.getsizeof(ciphertext)
    print(f"Total size of serialized HE ciphertexts: {soma} bytes")
    print("Soma 2:", soma2)
    print("Size of Seriliezed HE ciphertexts:", sys.getsizeof(serialized_he_ciphertexts))
    

    results.append({
        'size': size,
        'byte_array_size': sys.getsizeof(byte_array),
        'serialized_he_size': sys.getsizeof(serialized_he_ciphertexts),
        'total_he_size': soma2
    })

# Write all results to file
with open('communication_cost_pasta2.txt', 'w') as f:
    f.write("Size,Byte_Array_Size,Seerialized_HE_Size,Total_he_Size\n")
    for result in results:
        f.write(f"{result['size']},{result['byte_array_size']},{result['serialized_he_size']},{result['total_he_size']}\n")


