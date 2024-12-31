import pickle
import pandas as pd
import bz2
# model = pickle.load(open('pipe.pkl', 'rb'))

with bz2.open('your_file.pkl.bz2', 'rb') as f:
    model = pickle.load(f)

column =['Access_To_Healthy_Food', 'Age', 'Alchohol', 'Anxiety',
       'Blood_Glucose_Levels', 'CKD', 'COPD', 'Cancer', 'Cholesterol_Levels',
       'Creatinine_Levels', 'Depression', 'Diabetes', 'Discharge_To',
       'Distance_From_Hospital', 'Drugs', 'Education_Level',
       'Emergency_Visits', 'Employment_Status', 'Ethinicity',
       'Follow_Up_Attendance', 'Follow_Up_Scheduled', 'Gender', 'HIV/AIDS',
       'Health_Literacy', 'Heart_Diseases', 'Hemoglobin_Levels',
       'Hospital_Stay_Duration', 'Household_Composition', 'Housing_Stability',
       'Hypertension', 'IBD', 'Income_Level', 'Inflammatory_Markers',
       'Insurance_Type', 'Insurence_Coverage', 'Liver_Function_Tests',
       'Liver_Related_Conditions', 'Medication_Adherence', 'Medication_Type',
       'Neighborhood_Safety', 'Neurological_Disorders',
       'Number_Of_Medications', 'Osteoarthritis', 'Other',
       'Previous_Readmissions', 'Proactivity_In_Health',
       'Renal_Function_Tests', 'Side_Effects_And_Complications', 'Smoking',
       "Support System Availability"]

def prediction(data):
    row_to_predict_df = pd.DataFrame([data], columns=column)
    # print(data)
    result = model.predict(row_to_predict_df)
    return result