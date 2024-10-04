import re  # Import the 're' module for regular expression operations

# Function to assess the strength of the password
def assess_password_strength(password):
    # Criteria checks:
    length_criteria = len(password) >= 8  # Check if the length is at least 8 characters
    lowercase_criteria = bool(re.search(r'[a-z]', password))  # Check for lowercase letters
    uppercase_criteria = bool(re.search(r'[A-Z]', password))  # Check for uppercase letters
    digit_criteria = bool(re.search(r'\d', password))         # Check for digits (0-9)
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))  # Special characters

    # Count how many criteria are satisfied
    criteria_met = sum([
        length_criteria,
        lowercase_criteria,
        uppercase_criteria,
        digit_criteria,
        special_char_criteria
    ])

    # Determine password strength based on how many criteria are met
    if criteria_met == 5:
        strength = "Very Strong"
    elif criteria_met == 4:
        strength = "Strong"
    elif criteria_met == 3:
        strength = "Moderate"
    elif criteria_met == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    # Provide feedback on missing criteria
    feedback = []
    if not length_criteria:
        feedback.append("Password should be at least 8 characters long.")
    if not lowercase_criteria:
        feedback.append("Password should contain at least one lowercase letter.")
    if not uppercase_criteria:
        feedback.append("Password should contain at least one uppercase letter.")
    if not digit_criteria:
        feedback.append("Password should contain at least one digit.")
    if not special_char_criteria:
        feedback.append("Password should contain at least one special character (e.g., !, @, #, $).")

    # Return the strength and any feedback as output
    return strength, feedback

# Get user input for the password
password = input("Enter your password: ")

# Call the function to assess password strength and get feedback
strength, feedback = assess_password_strength(password)

# Display the password strength
print(f"Password strength: {strength}")

# If there are any feedback points, display them
if feedback:
    print("Suggestions for improvement:")
    for suggestion in feedback:
        print(f"- {suggestion}")
