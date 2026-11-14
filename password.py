import string


class PasswordAuditor:
    def __init__(self):
        self.common_passwords = [
            "password", "12345678", "qwerty123", "admin123",
            "welcome123", "iloveyou", "123456789", "football",
            "monkey", "letmein", "dragon", "baseball", "sunshine"
        ]

    def check_common_password(self, password):
        return password.lower() in self.common_passwords

    def has_repeated_chars(self, password):
        for i in range(len(password) - 2):
            if password[i] == password[i + 1] == password[i + 2]:
                return True
        return False

    def has_consecutive_chars(self, password):
        for i in range(len(password) - 2):
            c1 = ord(password[i].lower())
            c2 = ord(password[i + 1].lower())
            c3 = ord(password[i + 2].lower())
            if (c1 + 1 == c2 and c2 + 1 == c3) or (c1 - 1 == c2 and c2 - 1 == c3):
                if password[i:i + 3].isalnum():
                    return True
        return False

    def has_repeated_sequences(self, password):
        length = len(password)
        for size in range(2, (length // 2) + 1):
            for i in range(length - 2 * size + 1):
                if password[i:i + size] == password[i + size:i + 2 * size]:
                    return True
        return False

    def check_patterns(self, password):
        warnings = []

        if self.has_repeated_chars(password):
            warnings.append("Repeated characters detected (e.g., 'aaa' or '111').")

        if self.has_consecutive_chars(password):
            warnings.append("Consecutive alphanumeric sequence detected (e.g., '123' or 'abc').")

        if self.has_repeated_sequences(password):
            warnings.append("Repeated substring sequence detected (e.g., 'abcabc').")

        common_words = ["password", "welcome", "admin", "qwerty", "login", "user", "pass"]
        for word in common_words:
            if word in password.lower():
                warnings.append(f"Contains common word: '{word}'.")
                break

        return warnings

    def calculate_score(self, checks, is_common, pattern_warnings, length):
        score = 0

        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            score += 5

        if checks["uppercase"]:
            score += 10
        if checks["lowercase"]:
            score += 10
        if checks["numbers"]:
            score += 10
        if checks["special"]:
            score += 10

        if checks["no_repeats"]:
            score += 10
        if checks["no_consecutive"]:
            score += 10
        if checks["no_common_patterns"]:
            score += 10

        if is_common:
            score = min(score, 15)
        score -= len(pattern_warnings) * 5

        return max(0, min(100, score))

    def classify_score(self, score):
        if score <= 39:
            return "WEAK"
        elif score <= 69:
            return "MODERATE"
        elif score <= 89:
            return "STRONG"
        else:
            return "VERY STRONG"

    def audit_password(self, password):
        length = len(password)
        is_common = self.check_common_password(password)
        pattern_warnings = self.check_patterns(password)

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        checks = {
            "length_ok": length >= 8,
            "uppercase": has_upper,
            "lowercase": has_lower,
            "numbers": has_digit,
            "special": has_special,
            "no_repeats": not self.has_repeated_chars(password),
            "no_consecutive": not self.has_consecutive_chars(password),
            "no_common_patterns": (not is_common) and (len(pattern_warnings) == 0)
        }

        score = self.calculate_score(checks, is_common, pattern_warnings, length)
        strength = self.classify_score(score)

        print("\n" + "=" * 45)
        print("PASSWORD AUDIT RESULTS")
        print("=" * 45)
        print(f"Password Length : {length} characters")
        print(f"Security Score  : {score} / 100")
        print(f"Classification  : {strength}")
        print("-" * 45)

        print("Audit Checks:")
        for check_name, passed in checks.items():
            status = "PASS" if passed else "FAIL"
            print(f"  - {check_name.replace('_', ' ').title()}: {status}")

        if is_common:
            print("\n[!] WARNING: This password is in the commonly used passwords list!")

        if pattern_warnings:
            print("\n[!] Suspicious Pattern Warnings:")
            for warning in pattern_warnings:
                print(f"  * {warning}")

        print("=" * 45)


def main():
    auditor = PasswordAuditor()
    password = input("Enter a password to audit: ")
    if not password:
        print("Error: Password cannot be empty.")
    else:
        auditor.audit_password(password)


if __name__ == "__main__":
    main()
