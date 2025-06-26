import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib

from imblearn.over_sampling import SMOTE
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Load datasets
df = pd.read_csv('../AmpiricDataset/V4/final.csv')

# Separate features and labels
X = df.drop(columns=['Label'])
y = df['Label']

#############
def add_feature_noise(X, noise_level=0.01):
    X_noisy = X.copy()
    numeric_cols = X_noisy.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        noise = np.random.normal(loc=0.0, scale=noise_level, size=X_noisy[col].shape)
        X_noisy[col] += noise
    return X_noisy
def corrupt_labels(y, corruption_rate=0.03):
    y_corrupt = y.copy()
    num_to_corrupt = int(len(y) * corruption_rate)
    indices = np.random.choice(y.index, size=num_to_corrupt, replace=False)
    unique_classes = y.unique()
    for idx in indices:
        current_label = y[idx]
        new_label = np.random.choice([c for c in unique_classes if c != current_label])
        y_corrupt.at[idx] = new_label
    return y_corrupt
def dropout_features(X, dropout_rate=0.05):
    X_dropout = X.copy()
    mask = np.random.rand(*X_dropout.shape) < dropout_rate
    X_dropout[mask] = 0
    return X_dropout
# Apply transformations
X_noisy = add_feature_noise(X, noise_level=0.02)
X_dropout = dropout_features(X_noisy, dropout_rate=0.05)
y_corrupted = corrupt_labels(y, corruption_rate=0.03)
#############

# Standardize the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_dropout)

# Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_corrupted, test_size=0.2, random_state=42)

###############

# Build the Neural Network model
model = keras.Sequential([
    layers.Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
    layers.Dropout(0.5),  # Adding Dropout to reduce overfitting
    layers.Dense(64, activation='relu'),
    layers.Dropout(0.5),  # Another Dropout layer
    layers.Dense(32, activation='relu'),
    layers.Dense(1, activation='sigmoid')  # Binary classification
])

# Compile the model with a learning rate scheduler
initial_learning_rate = 0.001
lr_schedule = keras.optimizers.schedules.ExponentialDecay(
    initial_learning_rate,
    decay_steps=10000,
    decay_rate=0.9,
    staircase=True)

model.compile(optimizer=keras.optimizers.Adam(learning_rate=lr_schedule),
              loss='binary_crossentropy',
              metrics=['accuracy'])

# Implement EarlyStopping to avoid overfitting
early_stopping = keras.callbacks.EarlyStopping(monitor='val_loss', patience=5)

# Train the model with validation data and EarlyStopping
model.fit(X_train, y_train, epochs=50, batch_size=32, validation_data=(X_test, y_test), callbacks=[early_stopping])

# Evaluate the model
test_loss, test_acc = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {test_acc:.4f}")

# Make predictions
y_pred_prob = model.predict(X_test).ravel()
y_pred = (y_pred_prob > 0.5).astype(int)

# Classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred, digits=4))

# Confusion matrix
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ROC AUC score
roc_auc = roc_auc_score(y_test, y_pred_prob)
print(f"ROC AUC: {roc_auc:.4f}")


# Save the model
model.save('nn/nn_model.h5')

# Save the scaler
joblib.dump(scaler, 'nn/nn_scaler.pkl')