
from colorama import init, Fore, Style
import itertools
import sys

# Initialize colorama
init(autoreset=True)

# Global variable to track acceptance of terms
accepted_terms = False

# Define Terms of Usage agreement
terms_of_usage = """
Terms of Usage:

By using this program, you agree to comply with and be bound by the following terms and conditions of use:
1. You will use this program for lawful purposes only.
2. You will not engage in any activity that may harm the program or its users.
3. You accept all risks associated with the use of this program.

"""

# Function to display the Terms of Usage agreement
def display_terms_of_usage():
    print(terms_of_usage)

# Function to prompt the user to accept the Terms of Usage
def prompt_to_accept_terms():
    global accepted_terms
    while True:
        response = input("Do you accept the Terms of Usage? (yes/no): ").lower()
        if response == "yes":
            accepted_terms = True
            break
        elif response == "no":
            print("You must accept the Terms of Usage to use the program.")
            sys.exit()
        else:
            print("Please enter 'yes' or 'no'.")

# Main function to run the program
def main():
    global accepted_terms
    display_terms_of_usage()
    prompt_to_accept_terms()
    # If Terms of Usage accepted, proceed with program logic here
    if accepted_terms:
        print("Thank you for accepting the Terms of Usage. Proceeding with the program...")
        # Place your existing program logic here
        import hashlib
    import pyfiglet
    import random
    import string
    from colorama import init, Fore, Style
    import itertools

    # Initialize colorama
    init(autoreset=True)

    # Password Generator Function
    def generate_password(length=12, uppercase=True, lowercase=True, digits=True, symbols=True):
        characters = ""
        if uppercase:
            characters += string.ascii_uppercase
        if lowercase:
            characters += string.ascii_lowercase
        if digits:
            characters += string.digits
        if symbols:
            characters += string.punctuation

        if not characters:
            raise ValueError("At least one character set must be selected.")

        return ''.join(random.choice(characters) for _ in range(length))

    def detect_hash_type(input_hash):
        # Define constants for hash lengths
        SHA3_224_LENGTH = 56  # 56 hexadecimal characters (224 bits)
        SHA3_256_LENGTH = 64  # 64 hexadecimal characters (256 bits)
        SHA3_384_LENGTH = 96  # 96 hexadecimal characters (384 bits)
        SHA3_512_LENGTH = 128  # 128 hexadecimal characters (512 bits)
        SHA1_LENGTH = 40  # 40 hexadecimal characters (160 bits)
        SHA224_LENGTH = 56  # 56 hexadecimal characters (224 bits)
        SHA256_LENGTH = 64  # 64 hexadecimal characters (256 bits)
        SHA384_LENGTH = 96  # 96 hexadecimal characters (384 bits)
        SHA512_LENGTH = 128  # 128 hexadecimal characters (512 bits)
        MD5_LENGTH = 32  # 32 hexadecimal characters (128 bits)

        # Check if input hash matches SHA-3-224 length
        if len(input_hash) == SHA3_224_LENGTH:
            try:
                hashlib.sha3_224(bytes.fromhex(input_hash)).hexdigest()
                return "SHA3_224"
            except ValueError:
                pass

        # Check if input hash matches SHA-3-256 length
        if len(input_hash) == SHA3_256_LENGTH:
            try:
                hashlib.sha3_256(bytes.fromhex(input_hash)).hexdigest()
                return "SHA3_256"
            except ValueError:
                pass

        # Check if input hash matches SHA-3-384 length
        if len(input_hash) == SHA3_384_LENGTH:
            try:
                hashlib.sha3_384(bytes.fromhex(input_hash)).hexdigest()
                return "SHA3_384"
            except ValueError:
                pass

        # Check if input hash matches SHA-3-512 length
        if len(input_hash) == SHA3_512_LENGTH:
            try:
                hashlib.sha3_512(bytes.fromhex(input_hash)).hexdigest()
                return "SHA3_512"
            except ValueError:
                pass

        # Check if input hash matches SHA-224 length
        if len(input_hash) == SHA224_LENGTH:
            try:
                hashlib.sha224(bytes.fromhex(input_hash)).hexdigest()
                return "SHA224"
            except ValueError:
                pass

        # Check if input hash matches SHA-256 length
        if len(input_hash) == SHA256_LENGTH:
            try:
                hashlib.sha256(bytes.fromhex(input_hash)).hexdigest()
                return "SHA256"
            except ValueError:
                pass

        # Check if input hash matches SHA-384 length
        if len(input_hash) == SHA384_LENGTH:
            try:
                hashlib.sha384(bytes.fromhex(input_hash)).hexdigest()
                return "SHA384"
            except ValueError:
                pass

        # Check if input hash matches SHA-512 length
        if len(input_hash) == SHA512_LENGTH:
            try:
                hashlib.sha512(bytes.fromhex(input_hash)).hexdigest()
                return "SHA512"
            except ValueError:
                pass

        # Check if input hash matches SHA-1 length
        if len(input_hash) == SHA1_LENGTH:
            try:
                hashlib.sha1(bytes.fromhex(input_hash)).hexdigest()
                return "SHA1"
            except ValueError:
                pass

        # Check if input hash matches MD5 length
        if len(input_hash) == MD5_LENGTH:
            try:
                hashlib.md5(bytes.fromhex(input_hash)).hexdigest()
                return "MD5"
            except ValueError:
                pass

        # If the input hash length does not match any known hash length, return "Unknown"
        return "Unknown"

    def create_banner(text, font="standard", color=None):
        if color is None:
            return pyfiglet.figlet_format(text, font=font)
        else:
            return color + pyfiglet.figlet_format(text, font=font)

    def create_box(banner, additional_text):
        lines = banner.split('\n')
        max_length = max(len(line) for line in lines)
        box = '+' + '-' * (max_length + 2) + '+\n'
        for line in lines:
            box += '|' + line.center(max_length + 2) + '|\n'
        box += '|' + additional_text.center(max_length + 2) + '|\n'
        box += '+' + '-' * (max_length + 2) + '+'
        return box

    def validate_hash_algorithm(hash_algorithm):
        valid_algorithms = ["SHA256", "MD5", "SHA384", "SHA1", "SHA224", "SHA3_224", "SHA3_256", "SHA3_512",
                            "SHA512"]
        if hash_algorithm.upper() not in valid_algorithms:
            raise ValueError("Invalid hash algorithm specified.")

    def display_banner(text):
        banner_color = Fore.LIGHTYELLOW_EX
        banner = create_banner(text, font="slant", color=banner_color)
        additional_text = "Coded by Daniel. Contact on adeoluwademoye@gmail.com."
        boxed_banner = create_box(banner, additional_text)
        print(banner_color + boxed_banner)

    def banner():
        print(Style.RESET_ALL)
        display_banner("Hash Nerd")
        print(
            Fore.LIGHTCYAN_EX + "AVAILABLE HASHES: MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | SHA3_224 | SHA3_256 | SHA3_384 | SHA3_512 |")

    # Menu function to display options and handle user input
    banner1 = banner()
    print("1. Crack Hash From a File")
    print("2. Generate Password")
    print("3. Hash Comparison")
    print("4. Password Strength Checker")
    print("5. Hash Generator")
    print("6. Password complexity analysis")
    print("7. Bruteforce password")
    print("8. EXIT")

    while True:
        try:
            choice = int(input("Enter your choice (1-8): "))
            if choice < 1 or choice > 8:
                raise ValueError("Invalid choice. Please enter a number between 1 and 7.")
            else:
                break
        except ValueError as e:
            print(f"Error: {e}")

    if choice == 1:
        # Initialize colorama
        init(autoreset=True)

        def get_target_hash():
            try:
                target_hash = input(Fore.LIGHTYELLOW_EX + "Enter the hash to crack: ")
                return target_hash
            except Exception as e:
                print(Fore.RED + f"Error: {e}")
                exit()

        def get_target_path():
            try:
                target_path = input(Fore.LIGHTYELLOW_EX + "Enter the path to the file: ")
                return target_path
            except Exception as e:
                print(Fore.RED + f"Error: {e}")
                exit()

        # Function to crack hash

        # Function to crack hash
        def crack_hash(target_hash, password_list):
            target_hash_lower = target_hash.lower()

            for password in password_list:
                password = password.strip()

                if hashlib.md5(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha1(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha224(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha256(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha384(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha512(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha3_224(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha3_256(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha3_384(password.encode()).hexdigest() == target_hash_lower:
                    return password
                elif hashlib.sha3_512(password.encode()).hexdigest() == target_hash_lower:
                    return password

            return None  # Return None if password is not found

        # Read target hash
        target_hash = input("Enter the hash to crack: ")

        # Read passwords from a file
        password_file = input("Enter the path to the password file: ")
        with open(password_file, "r", encoding="latin-1") as file:
            passwords = file.readlines()

        # Crack the hash
        cracked_password = crack_hash(target_hash, passwords)

        # Print the result
        if cracked_password:
            print(f"Password cracked: {cracked_password}")
        else:
            print("Password not found in the list.")

    if choice == 2:
        try:
            length = int(input("Enter length of password:"))

            str_value = input("Do you want uppercase in the password(True/False): ")
            bool_value = True if str_value.lower() == "true" else False

            lower_case = input("Do you want lowercase in the password(True/False): ")
            bool_value2 = True if lower_case.lower() == "true" else False

            digits = input("Do you want digits in the password(True/False): ")
            bool_value3 = True if digits.lower() == "true" else False

            symbols = input("Do you want digits in the password(True/False): ")
            bool_value4 = True if digits.lower() == "true" else False

            new = generate_password(length, bool_value, bool_value2, bool_value3, bool_value4)
            print(f"Your generated password is  {new}")
        except Exception as e:
            print(f"Error: {e}")

    if choice == 3:
        import hashlib
        choose = input('Do you want to perform multiple or single hash comparison(single/multiple): ')
        choose.lower()

        if choose == 'single':
            print("\nHash Comparison")
            target_hash = input('Enter the target hash: ')
            hash_stuff = detect_hash_type(target_hash)
            print("Detected Hash Type:", hash_stuff)
            plaintext_password = input("Enter the plaintext password: ")

            hash_type = hash_stuff
            hash_type.upper()

            hashed_password = None
            if hash_type == "MD5":
                hashed_password = hashlib.md5(plaintext_password.encode()).hexdigest()
            elif hash_type == "SHA1":
                hashed_password = hashlib.sha1(plaintext_password.encode()).hexdigest()

            elif hash_type == "SHA224":
                hashed_password = hashlib.sha224(plaintext_password.encode()).hexdigest()

            elif hash_type == "SHA256":
                hashed_password = hashlib.sha1(plaintext_password.encode()).hexdigest()

            elif hash_type == "SHA384":
                hashed_password = hashlib.sha1(plaintext_password.encode()).hexdigest()

            elif hash_type == "SHA512":
                hashed_password = hashlib.sha512(plaintext_password.encode()).hexdigest()

            elif hash_type == "SHA3_224":
                hashed_password = hashlib.sha3_224(plaintext_password.encode()).hexdigest()

            elif hash_type == "SHA3_256":
                hashed_password = hashlib.sha3_256(plaintext_password.encode()).hexdigest()

            elif hash_type == "SHA3_384":
                hashed_password = hashlib.sha3_384(plaintext_password.encode()).hexdigest()

            elif hash_type == "SHA3_512":
                hashed_password = hashlib.sha3_512(plaintext_password.encode()).hexdigest()

            if hashed_password and hashed_password == target_hash:
                print(Fore.LIGHTGREEN_EX + "Password cracked:", plaintext_password)
                stuff = input('Do you want to write the cracked password to a file(yes/no): ')
                stuff.lower()
                if stuff == "yes":
                    print("")
                    new_path = input('Enter path to write the cracked password to: ')

                    def write_cracked_passwords_to_file(file_path, cracked_passwords):
                        try:
                            with open(file_path, "w") as file:
                                file.write(f"{cracked_passwords}\n")
                            print("Cracked passwords saved to file.")
                        except Exception as e:
                            print(f"Error: {e}")

                    write_cracked_passwords_to_file(new_path, plaintext_password)

                elif stuff == "no":
                    print("Bye Then")

            else:
                print(Fore.RED + "Password not cracked.")


        elif choose == "multiple":

            def hash_comparison2():
                print("\nHash Comparison")
                target_hashes = input("Enter target hashes (separated by space): ").split()
                hash_types = [detect_hash_type(target_hash) for target_hash in target_hashes]
                print("Detected Hash Types:", hash_types)

                plaintext_password = input("Enter the plaintext password: ")

                for hash_type, target_hash in zip(hash_types, target_hashes):
                    hashed_password = None
                    if hash_type == "MD5":
                        hashed_password = hashlib.md5(plaintext_password.encode()).hexdigest()
                    elif hash_type == "SHA1":
                        hashed_password = hashlib.sha1(plaintext_password.encode()).hexdigest()

                    elif hash_type == "SHA224":
                        hashed_password = hashlib.sha224(plaintext_password.encode()).hexdigest()

                    elif hash_type == "SHA256":
                        hashed_password = hashlib.sha256(plaintext_password.encode()).hexdigest()

                    elif hash_type == "SHA512":
                        hashed_password = hashlib.sha512(plaintext_password.encode()).hexdigest()

                    elif hash_type == "SHA384":
                        hashed_password = hashlib.sha384(plaintext_password.encode()).hexdigest()

                    elif hash_type == "SHA3_224":
                        hashed_password = hashlib.sha3_224(plaintext_password.encode()).hexdigest()

                    elif hash_type == "SHA3_512":
                        hashed_password = hashlib.sha3_512(plaintext_password.encode()).hexdigest()

                    elif hash_type == "SHA3_384":
                        hashed_password = hashlib.sha3_384(plaintext_password.encode()).hexdigest()

                    elif hash_type == "SHA3_256":
                        hashed_password = hashlib.sha3_256(plaintext_password.encode()).hexdigest()

                    if hashed_password and hashed_password == target_hash:
                        print("Password cracked for", target_hash, ":", plaintext_password)
                    else:
                        print("Password not cracked for", target_hash)

            hash_comparison2()

    if choice == 4:
        def check_password_strength(password):
            # Define password strength criteria
            min_length = 8
            has_uppercase = any(char.isupper() for char in password)
            has_lowercase = any(char.islower() for char in password)
            has_digit = any(char.isdigit() for char in password)
            has_symbol = any(char in string.punctuation for char in password)

            # Evaluate password strength
            strength = "Weak"
            if len(password) >= min_length and has_uppercase and has_lowercase and has_digit and has_symbol:
                strength = "Strong"
            elif len(password) >= min_length and (has_uppercase or has_lowercase) and has_digit:
                strength = "Moderate"

            return strength

        # Example usage:
        password = input("Input your password: ")
        strength = check_password_strength(password)
        print(f"Password Strength: {strength}")

    if choice == 5:
        try:
            def hash_password(password, hash_algorithm):
                password_bytes = password.encode(encoding="latin-1")

                if hash_algorithm.upper() == "SHA256":
                    hashed_stuff = hashlib.sha256(password_bytes).hexdigest()
                elif hash_algorithm.upper() == "MD5":
                    hashed_stuff = hashlib.md5(password_bytes).hexdigest()
                elif hash_algorithm.upper() == "SHA384":
                    hashed_stuff = hashlib.sha384(password_bytes).hexdigest()
                elif hash_algorithm.upper() == "SHA1":
                    hashed_stuff = hashlib.sha1(password_bytes).hexdigest()
                elif hash_algorithm.upper() == "SHA224":
                    hashed_stuff = hashlib.sha224(password_bytes).hexdigest()
                elif hash_algorithm.upper() == "SHA3_224":
                    hashed_stuff = hashlib.sha3_224(password_bytes).hexdigest()
                elif hash_algorithm.upper() == "SHA3_256":
                    hashed_stuff = hashlib.sha3_256(password_bytes).hexdigest()
                elif hash_algorithm.upper() == "SHA3_512":
                    hashed_stuff = hashlib.sha3_512(password_bytes).hexdigest()
                elif hash_algorithm.upper() == "SHA512":
                    hashed_stuff = hashlib.sha512(password_bytes).hexdigest()
                else:
                    raise ValueError("Incorrect hash algorithm specified.")

                return hashed_stuff

            try:
                password = input("Enter text to be hashed: ")
                hash_algo = input('Which Hash Algorithm should be used for hashing: ')
                validate_hash_algorithm(hash_algo)
                hashed_password = hash_password(password, hash_algo)
                print("This is the hashed text:", hashed_password)
            except ValueError as e:
                print("Error:", e)
            except Exception as e:
                print("An error occurred:", e)


        except Exception as e:
            print(f"Error: {e}")

    if choice == 6:
        import string

        def analyze_password_complexity(nao):
            complexity_score = 0

            # Check length and add score
            if len(nao) >= 8:
                complexity_score += 2
            elif len(nao) >= 6:
                complexity_score += 1

            # Check for uppercase letters and add score
            if any(char.isupper() for char in password):
                complexity_score += 2

            # Check for lowercase letters and add score
            if any(char.islower() for char in password):
                complexity_score += 2

            # Check for digits and add score
            if any(char.isdigit() for char in password):
                complexity_score += 2

            # Check for special characters and add score
            if any(char in string.punctuation for char in password):
                complexity_score += 2

            common_patterns = ['123', 'abc', 'password', 'qwerty', 'admin', 'password123']
            if any(pattern in password.lower() for pattern in common_patterns):
                complexity_score = 0

            return complexity_score

        password = input("Enter your password: ")
        score = analyze_password_complexity(password)

        if score >= 10:
            print(f"Your password scored {score} out of 10")
        elif score >= 7:
            print(f"Your password scored {score} out of 10")
        elif score >= 5:
            print(f"Your password scored {score} out of 10")
        else:
            print(f"Your password scored {score} out of 10")

    if choice == 7:
       print("1. Brute force based on password owner information: ")
       print("2. Brute force using all possible combination of character set: ")
       while True:
           try:
               bruteforce_choice = int(input("Enter your choice (1-2): "))
               if bruteforce_choice < 1 or bruteforce_choice > 2:
                   raise ValueError("Invalid choice. Please enter a number between 1 and 2.")
               else:
                   break
           except ValueError as e:
               print(f"Error: {e}")

       if bruteforce_choice == 2:
           def generate_passwords(length, charset, include_space):
               """
               Generate all possible passwords of a given length using the characters in the charset.
               """
               if length == 0:
                   yield ''
               else:
                   for char in charset:
                       for password in generate_passwords(length - 1, charset, include_space):
                           if include_space:
                               yield char + ' ' + password
                           else:
                               yield char + password

           def hash_password(password, hash_algorithm):
               """
               Hashes a password using the specified hash algorithm.
               """
               hash_func = getattr(hashlib, hash_algorithm, None)
               if hash_func:
                   return hash_func(password.encode()).hexdigest()
               else:
                   raise ValueError("Hash algorithm not supported.")

           def guess_hash_algorithm(hash_to_crack):
               """
               Guess the hash algorithm based on the hash length.
               """
               hash_length = len(hash_to_crack)
               if hash_length == 32:
                   return "md5"
               elif hash_length == 40:
                   return "sha1"
               elif hash_length == 56:
                   return "sha224"
               elif hash_length == 64:
                   if hash_to_crack.startswith("sha3_"):
                       return "sha3_512"
                   else:
                       return "sha256"
               elif hash_length == 96:
                   if hash_to_crack.startswith("sha3_"):
                       return "sha3_384"
                   else:
                       return "sha384"
               elif hash_length == 128:
                   if hash_to_crack.startswith("sha3_"):
                       return "sha3_256"
                   else:
                       return "sha512"
               else:
                   raise ValueError("Unable to guess hash algorithm.")

           def calculate_combinations(charset_size, min_length, max_length):
               """
               Calculate the number of possible combinations based on charset size and password length.
               """
               total_combinations = sum(charset_size ** length for length in range(min_length, max_length + 1))
               if total_combinations >= 700000:
                   print(Fore.LIGHTRED_EX + "MAN THIS IS MUCH")
                   return Fore.LIGHTRED_EX + str(total_combinations)

               elif total_combinations <= 700000:
                   print(Fore.LIGHTGREEN_EX + "PLAUSIBLE")
                   return Fore.LIGHTGREEN_EX + str(total_combinations)

           def brute_force(hash_to_crack, charset, min_length, max_length, hash_algorithm, include_space):
               """
               Brute-force a hash by trying all possible passwords of lengths up to max_length.
               """
               print("Brute forcing password...")
               total_passwords_tried = 0
               last_password_tried = ''
               for length in range(min_length, max_length + 1):
                   for password in generate_passwords(length, charset, include_space):
                       total_passwords_tried += 1
                       sys.stdout.write(Fore.LIGHTRED_EX + f" \rTried {total_passwords_tried} passwords ")
                       sys.stdout.flush()
                       hashed_password = hash_password(password, hash_algorithm)
                       if hashed_password == hash_to_crack:
                           return password, total_passwords_tried
                       last_password_tried = password
               print("\nLast password tried: " + last_password_tried)
               return None, total_passwords_tried

               # Example usage:

           hash_to_crack = input("Enter the hash to crack: ")
           include_uppercase = input("Include uppercase letters? (y/n): ").lower() == "y"
           include_lowercase = input("Include lowercase letters? (y/n): ").lower() == "y"
           include_digits = input("Include digits? (y/n): ").lower() == "y"
           include_symbols = input("Include symbols? (y/n): ").lower() == "y"
           include_space = input("Include space between characters? (y/n): ").lower() == "y"
           min_length = int(input("Enter the minimum password length to try: "))
           max_length = int(input("Enter the maximum password length to try: "))

           charset_size = 0
           if include_uppercase:
               charset_size += len(string.ascii_uppercase)
           if include_lowercase:
               charset_size += len(string.ascii_lowercase)
           if include_digits:
               charset_size += len(string.digits)
           if include_symbols:
               charset_size += len(string.punctuation)

           total_combinations = calculate_combinations(charset_size, min_length, max_length)
           print("Total possible combinations:", total_combinations)

           charset = ''
           if include_uppercase:
               charset += string.ascii_uppercase
           if include_lowercase:
               charset += string.ascii_lowercase
           if include_digits:
               charset += string.digits
           if include_symbols:
               charset += string.punctuation

           hash_algorithm = guess_hash_algorithm(hash_to_crack)

           cracked_password, total_passwords_tried = brute_force(hash_to_crack, charset, min_length, max_length,
                                                                 hash_algorithm,
                                                                 include_space)
           if cracked_password:
               print(Fore.LIGHTGREEN_EX + "Password cracked: " + cracked_password)


       elif bruteforce_choice == 1:

           # Expanded SocialMediaAPI class

           class SocialMediaAPI:
               def __init__(self):
                   # Mock data for demonstration
                   self.users = {
                       "user1": {"name": "User One", "friends": ["user2", "user3"], "posts": ["post1", "post2"]},
                       "user2": {"name": "User Two", "friends": ["user1"], "posts": ["post3"]},
                       "user3": {"name": "User Three", "friends": ["user1"], "posts": []}
                   }
                   self.posts = {
                       "post1": {"content": "Post 1 Content", "likes": 10, "comments": ["comment1", "comment2"]},
                       "post2": {"content": "Post 2 Content", "likes": 20, "comments": ["comment3"]},
                       "post3": {"content": "Post 3 Content", "likes": 5, "comments": []}
                   }
                   self.comments = {
                       "comment1": {"author": "user2", "content": "Comment 1 Content"},
                       "comment2": {"author": "user3", "content": "Comment 2 Content"},
                       "comment3": {"author": "user1", "content": "Comment 3 Content"}
                   }
                   self.notifications = {
                       "user1": {"friend_requests": ["user4"], "likes": 3, "comments": 2}
                   }
                   self.groups = {
                       "group1": {"name": "Group One", "members": ["user1", "user2"],
                                  "description": "Description of Group One"}
                   }
                   # Assume additional data structures and methods for other features

               def get_user_info(self, username):
                   # Retrieve user information
                   return self.users.get(username, {})

               def get_user_friends(self, username):
                   # Retrieve user's friends
                   user = self.users.get(username, {})
                   return user.get("friends", [])

               def get_user_posts(self, username):
                   # Retrieve user's posts
                   user = self.users.get(username, {})
                   posts = user.get("posts", [])
                   return [self.posts.get(post, {}) for post in posts]

               def get_post_likes(self, post_id):
                   # Retrieve likes for a post
                   post = self.posts.get(post_id, {})
                   return post.get("likes", 0)

               def get_post_comments(self, post_id):
                   # Retrieve comments for a post
                   post = self.posts.get(post_id, {})
                   comments = post.get("comments", [])
                   return [self.comments.get(comment, {}) for comment in comments]

               def get_notifications(self, username):
                   # Retrieve notifications for a user
                   return self.notifications.get(username, {})

               def get_group_info(self, group_id):
                   # Retrieve information about a group
                   return self.groups.get(group_id, {})

               # Additional methods for other features...

           def generate_passwords(profile):
               """
               Generate passwords based on personal information in the profile.
               """
               passwords = []

               # Extract relevant personal information from the profile
               name = profile.get("name", "")
               dob_year = profile.get("dob_year", "")
               dob_month = profile.get("dob_month", "")
               dob_day = profile.get("dob_day", "")
               pet_name = profile.get("pet_name", "")
               spouse_name = profile.get("spouse_name", "")
               child_name = profile.get("child_name", "")
               favorite_number = profile.get("favorite_number", "")

               # Initialize SocialMediaAPI
               social_media_api = SocialMediaAPI()
               username = profile.get("username", "")

               # Get additional information from social media API
               social_media_info = social_media_api.get_user_info(username)
               interests = social_media_info.get("interests", [])
               quotes = social_media_info.get("quotes", [])
               friends = social_media_api.get_user_friends(username)
               notifications = social_media_api.get_notifications(username)

               # Additional personal information
               additional_info = interests + quotes + friends + list(notifications.keys())

               # Combine personal information and additional info
               personal_info = [name, dob_year, dob_month, dob_day, pet_name, spouse_name, child_name, favorite_number]
               personal_info += additional_info

               # Generate passwords based on various combinations and permutations of the personal information
               # You can customize this based on common patterns and combinations you want to include
               patterns = [
                   # Basic patterns
                   name,
                   dob_year,
                   dob_month,
                   dob_day,
                   pet_name,
                   spouse_name,
                   child_name,
                   favorite_number,
                   # Combination of basic patterns
                   name + dob_year,
                   name + dob_month,
                   name + dob_day,
                   name + pet_name,
                   name + spouse_name,
                   name + child_name,
                   dob_year + dob_month,
                   dob_year + dob_day,
                   dob_year + pet_name,
                   dob_year + spouse_name,
                   dob_year + child_name,
                   dob_month + dob_day,
                   dob_month + pet_name,
                   dob_month + spouse_name,
                   dob_month + child_name,
                   dob_day + pet_name,
                   dob_day + spouse_name,
                   name + "@" + dob_year,
                   name + "@" + dob_month,
                   name + "@" + dob_day,
                   dob_day + child_name,
                   pet_name + spouse_name,
                   pet_name + child_name,
                   spouse_name + child_name,
                   # Additional patterns based on interests and quotes
                   *interests,
                   *quotes
               ]

               # Additional substitution patterns
               for pattern in patterns:
                   for substitute in ["", "!", "#", "$", "&"]:
                       passwords.append(
                           pattern.replace("a", "@").replace("e", "3").replace("o", "0").replace("i", "1").replace("s",
                                                                                                                   "$").replace(
                               "t", "7").replace("l", "1").replace("g", "9").replace("z", "2").replace("q",
                                                                                                       "9").replace(
                               "b", "8") + substitute)

               # Generate more combinations of basic patterns with symbols
               for i in range(len(patterns)):
                   for j in range(i + 1, len(patterns)):
                       password = patterns[i] + patterns[j]
                       password += ''.join(random.choices(string.punctuation, k=3))  # Add 3 random symbols
                       passwords.append(password)
                       passwords.append(password[::-1])  # Reversed combination

               # Generate passwords based on combinations of the defined patterns
               for pattern in patterns:
                   # Generate variations of the pattern using different separators and permutations
                   for separator in ["", ".", "-", "_", ""]:
                       for permuted_pattern in itertools.permutations(pattern.split()):
                           password = separator.join(permuted_pattern)
                           passwords.append(password)

               print("Number of generated passwords:", len(passwords))
               return passwords

           def get_user_profile():
               """
               Prompt the user for personal information and return a profile dictionary.
               """
               print(Fore.LIGHTGREEN_EX + "PROVIDE INFORMATION")
               name = input("Name: ").strip()
               dob_year = input("Year of Birth: ").strip()
               dob_month = input("Month of Birth: ").strip()
               dob_day = input("Day of Birth: ").strip()
               pet_name = input("Pet's Name: ").strip()
               spouse_name = input("Spouse's Name: ").strip()
               child_name = input("Child's Name: ").strip()
               favorite_number = input("Favorite Number: ").strip()
               username = input("Social Media Username: ").strip()

               profile = {
                   "name": name,
                   "dob_year": dob_year,
                   "dob_month": dob_month,
                   "dob_day": dob_day,
                   "pet_name": pet_name,
                   "spouse_name": spouse_name,
                   "child_name": child_name,
                   "favorite_number": favorite_number,
                   "username": username
               }
               return profile

           hash_algorithm = input("Enter hash algorithm: ").lower()

           def hash_password(password):
               # Convert to lowercase here
               if hash_algorithm == "md5":
                   return hashlib.md5(password.encode()).hexdigest()
               elif hash_algorithm == 'sha256':
                   return hashlib.sha256(password.encode()).hexdigest()
               elif hash_algorithm == 'sha1':
                   return hashlib.sha1(password.encode()).hexdigest()
               elif hash_algorithm == 'sha224':
                   return hashlib.sha224(password.encode()).hexdigest()
               elif hash_algorithm == 'sha384':
                   return hashlib.sha384(password.encode()).hexdigest()
               elif hash_algorithm == 'sha512':
                   return hashlib.sha512(password.encode()).hexdigest()
               elif hash_algorithm == 'sha3_224':
                   return hashlib.sha3_224(password.encode()).hexdigest()
               elif hash_algorithm == 'sha3_256':
                   return hashlib.sha3_256(password.encode()).hexdigest()
               elif hash_algorithm == 'sha3_384':
                   return hashlib.sha3_384(password.encode()).hexdigest()
               elif hash_algorithm == 'sha3_512':
                   return hashlib.sha3_512(password.encode()).hexdigest()

           def brute_force_hash(target_hash, passwords):
               """
               Brute force comparison of hashed passwords with the target hash.
               """
               for password in passwords:
                   hashed_password = hash_password(password)
                   if hashed_password == target_hash:
                       return password
               return None

           # Example usage:
           if __name__ == "__main__":
               # Get the user's profile
               user_profile = get_user_profile()

               # Generate passwords based on the user's profile
               generated_passwords = generate_passwords(user_profile)

               # Get the target hash from the user
               target_hash = input("Enter the target hash: ").strip()

               # Perform brute-force comparison
               found_password = brute_force_hash(target_hash, generated_passwords)

               # Print the result
               if found_password:
                   print(Fore.LIGHTGREEN_EX + f"Password cracked: {found_password}")
               else:
                   print(Fore.LIGHTRED_EX + "Status:Exhausted" + "Password not found")


if __name__ == "__main__":
     main()
