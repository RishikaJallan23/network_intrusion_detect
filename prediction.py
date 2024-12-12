import pickle
import tensorflow as tf
import numpy as np
import pandas as pd
import warnings
from mitigation import get_mitigation_for_attack

warnings.filterwarnings("ignore")

# Load the trained model
model = tf.keras.models.load_model("models/ArtificialNeuralNetwork_model.keras")

# Load the important features used for training
with open("models/Important_Features.pkl", "rb") as file:
    imp_cols = pickle.load(file)

# Load the scaler for feature normalization
with open("models/Scaler.pkl", "rb") as file:
    scaler = pickle.load(file)

# Define the class labels
class_labels = ['Benign', 'DDOS', 'Password', 'Scanning']

# Function to update the log file with detected attacks
def update_logfile(ip_address, predicted_attack):
    new_data = {'IP Address': [ip_address], 'Found Attack': [predicted_attack]}
    new_row_df = pd.DataFrame(new_data)

    try:
        df = pd.read_csv("LOG.csv")
    except FileNotFoundError:
        df = pd.DataFrame(columns=['IP Address', 'Found Attack'])

    df = pd.concat([df, new_row_df], ignore_index=True)
    df.to_csv("LOG.csv", index=False)

# Phase 1: Check if the IP exists in the log
def phase_1_verification(filepath):
    df = pd.read_csv(filepath)
    ip_address = df.pop('IP').values[0].strip()

    try:
        ip_df = pd.read_csv("LOG.csv")
    except FileNotFoundError:
        return {"STATUS": False}

    if ip_address in ip_df['IP Address'].values:
        attack = ip_df.loc[ip_df['IP Address'] == ip_address, 'Found Attack'].values[0]
        return {"STATUS": True, "IP ADDRESS": ip_address, "ATTACK": attack}
    else:
        return {"STATUS": False}

# Phase 2: Predict attack type if not found in the log
def phase_2_verification(filepath):
    df = pd.read_csv(filepath)
    ip_address = df.pop('IP').values[0].strip()

    try:
        df_selected = df[imp_cols]
    except KeyError as e:
        missing_cols = set(imp_cols) - set(df.columns)
        raise ValueError(f"Missing columns: {missing_cols}")

    # Normalize the data
    df_scaled = scaler.transform(df_selected.values)
    prediction = model.predict(df_scaled)
    
    # Get the predicted class label (index of highest probability)
    class_label = np.argmax(prediction)
    class_name = class_labels[class_label]

    # Debugging: print predicted attack
    print(f"Predicted attack: {class_name}")

    # If the attack is not benign, log it
    if class_name != 'Benign':
        update_logfile(ip_address, class_name)
        print(f"Updated log for IP: {ip_address} with attack: {class_name}")
    
    return ip_address, class_name

# Main prediction function
def predict_res(filepath):
    try:
        # Phase 1: Check if the IP is already logged
        phase_1_status = phase_1_verification(filepath)
        if phase_1_status['STATUS']:
            return (f"The IP address {phase_1_status['IP ADDRESS']} is blocked.",
                    f"Attack details: {phase_1_status['ATTACK']}", "")

        # Phase 2: Predict attack type if not found in the log
        ip_address, class_name = phase_2_verification(filepath)

        # Normalize the class_name for mitigation measures lookup
        class_name_normalized = class_name.strip().lower()
        print(f"Normalized Class Name: {class_name_normalized}")  # Debugging log

        # Handle benign case
        if class_name_normalized == 'benign':
            return (f"The IP address {ip_address} is safe.",
                    f"Traffic Type: {class_name_normalized}",
                    "No action needed. Normal traffic detected.")

        # Get mitigation measures dynamically for non-benign cases
        mitigation_measures = get_mitigation_for_attack(class_name_normalized)

        # Convert mitigation measures to a string with each measure on a new line
        mitigation_text = "\n".join([f"- {measure}" for measure in mitigation_measures])

        return (f"The IP address {ip_address} is under attack!",
                f"Attack Type: {class_name_normalized}",
                mitigation_text)

    except Exception as e:
        # Log the error for debugging and return a failure message
        print(f"Error in prediction: {str(e)}")
        return ("Prediction failed.", str(e), "")


# Main function to test prediction
if __name__ == "__main__":
    test_filepath = "labelled/DDOS.csv"  # Ensure this file exists
    result = predict_res(test_filepath)
    print(result[0])  # Should show attack type and status
    print(result[1])  # Attack details (e.g., DDOS or other)
    print(result[2])  # Mitigation measures (specific to attack type)
