import re
import secrets
import string


def evaluate_password(password):
    # Criteria indicators
    checks = {
        "length": len(password) >= 10,
        "upper": re.search(r'[A-Z]', password) is not None,
        "lower": re.search(r'[a-z]', password) is not None,
        "digit": re.search(r'\d', password) is not None,
        "special": re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None
    }

    # Calculate score
    score = sum(checks.values())

    if score < 3:
        strength = "Weak"
    elif score < 5:
        strength = "Moderate"
    else:
        strength = "Strong"

    return strength, checks


def generate_suggestion():
    # Create a strong 12-character password
    characters = string.ascii_letters + string.digits + "!@#$%^*"
    return ''.join(secrets.choice(characters) for _ in range(12))


# Test it out
if __name__ == "__main__":
    p = input("Enter a password to test: ")
    res, details = evaluate_password(p)
    print(f"Strength: {res} | Details: {details}")