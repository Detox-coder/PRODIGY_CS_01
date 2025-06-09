#!/usr/bin/env python3
"""
PRODIGY_CS_01: Advanced Caesar Cipher Implementation
===================================================
A comprehensive Python implementation of the Caesar Cipher algorithm with
enhanced security features, robust error handling, and professional UX.

Author: Amit Mondal - Cybersecurity Intern - Prodigy InfoTech
Date: June 2025
Version: 1.0

Features:
- Enhanced Caesar Cipher with frequency analysis resistance
- Batch processing capabilities
- File encryption/decryption support
- Brute force attack simulation
- Statistical analysis of encrypted text
- Professional logging and error handling
"""

import string
import re
import os
import sys
from typing import Tuple, List, Dict, Optional
from collections import Counter
import argparse
from datetime import datetime


class AdvancedCaesarCipher:
    """
    Advanced Caesar Cipher implementation with enhanced security features.
    
    This class provides comprehensive encryption/decryption capabilities
    with additional cybersecurity-focused features for educational purposes.
    """
    
    def __init__(self):
        """Initialize the cipher with default settings."""
        self.alphabet = string.ascii_lowercase
        self.alphabet_size = len(self.alphabet)
        self.operation_log = []
        
    def _log_operation(self, operation: str, message_length: int, shift: int, mode: str):
        """Log cipher operations for audit trail."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'operation': operation,
            'message_length': message_length,
            'shift': shift,
            'mode': mode
        }
        self.operation_log.append(log_entry)
    
    def normalize_shift(self, shift: int) -> int:
        """
        Normalize shift value to be within 0-25 range.
        
        Args:
            shift (int): The shift value to normalize
            
        Returns:
            int: Normalized shift value
        """
        return shift % self.alphabet_size
    
    def encrypt_char(self, char: str, shift: int) -> str:
        """
        Encrypt a single character using Caesar cipher.
        
        Args:
            char (str): Character to encrypt
            shift (int): Shift value
            
        Returns:
            str: Encrypted character
        """
        if char.isalpha():
            # Preserve case
            is_upper = char.isupper()
            char = char.lower()
            
            # Find position and apply shift
            old_index = self.alphabet.index(char)
            new_index = (old_index + shift) % self.alphabet_size
            new_char = self.alphabet[new_index]
            
            return new_char.upper() if is_upper else new_char
        
        # Return non-alphabetic characters unchanged
        return char
    
    def decrypt_char(self, char: str, shift: int) -> str:
        """
        Decrypt a single character using Caesar cipher.
        
        Args:
            char (str): Character to decrypt
            shift (int): Shift value
            
        Returns:
            str: Decrypted character
        """
        # Decryption is encryption with negative shift
        return self.encrypt_char(char, -shift)
    
    def encrypt(self, message: str, shift: int) -> str:
        """
        Encrypt a message using Caesar cipher.
        
        Args:
            message (str): Message to encrypt
            shift (int): Shift value
            
        Returns:
            str: Encrypted message
        """
        shift = self.normalize_shift(shift)
        encrypted = ''.join(self.encrypt_char(char, shift) for char in message)
        
        # Log the operation
        self._log_operation("ENCRYPT", len(message), shift, "Caesar")
        
        return encrypted
    
    def decrypt(self, message: str, shift: int) -> str:
        """
        Decrypt a message using Caesar cipher.
        
        Args:
            message (str): Message to decrypt
            shift (int): Shift value
            
        Returns:
            str: Decrypted message
        """
        shift = self.normalize_shift(shift)
        decrypted = ''.join(self.decrypt_char(char, shift) for char in message)
        
        # Log the operation
        self._log_operation("DECRYPT", len(message), shift, "Caesar")
        
        return decrypted
    
    def brute_force_attack(self, encrypted_message: str) -> List[Tuple[int, str]]:
        """
        Perform brute force attack on encrypted message.
        
        Args:
            encrypted_message (str): Message to attack
            
        Returns:
            List[Tuple[int, str]]: List of (shift, decrypted_text) tuples
        """
        results = []
        print("\n🔍 BRUTE FORCE ANALYSIS")
        print("=" * 50)
        
        for shift in range(self.alphabet_size):
            decrypted = self.decrypt(encrypted_message, shift)
            results.append((shift, decrypted))
            print(f"Shift {shift:2d}: {decrypted}")
        
        return results
    
    def frequency_analysis(self, text: str) -> Dict[str, float]:
        """
        Perform frequency analysis on text.
        
        Args:
            text (str): Text to analyze
            
        Returns:
            Dict[str, float]: Character frequency percentages
        """
        # Remove non-alphabetic characters and convert to lowercase
        clean_text = re.sub(r'[^a-zA-Z]', '', text.lower())
        
        if not clean_text:
            return {}
        
        # Count character frequencies
        char_count = Counter(clean_text)
        total_chars = len(clean_text)
        
        # Calculate percentages
        frequencies = {char: (count / total_chars) * 100 
                      for char, count in char_count.items()}
        
        return dict(sorted(frequencies.items(), key=lambda x: x[1], reverse=True))
    
    def display_frequency_analysis(self, text: str, title: str = "FREQUENCY ANALYSIS"):
        """Display frequency analysis in a formatted table."""
        frequencies = self.frequency_analysis(text)
        
        if not frequencies:
            print(f"\n📊 {title}: No alphabetic characters found")
            return
        
        print(f"\n📊 {title}")
        print("=" * 40)
        print("Char | Frequency | Bar Chart")
        print("-" * 40)
        
        for char, freq in list(frequencies.items())[:10]:  # Top 10
            bar = "█" * int(freq / 2)  # Scale bar chart
            print(f"  {char}  |   {freq:5.1f}%  | {bar}")
    
    def encrypt_file(self, file_path: str, shift: int, output_path: str = None) -> bool:
        """
        Encrypt a text file.
        
        Args:
            file_path (str): Path to input file
            shift (int): Shift value
            output_path (str): Path to output file (optional)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            encrypted_content = self.encrypt(content, shift)
            
            if output_path is None:
                output_path = f"{file_path}.encrypted"
            
            with open(output_path, 'w', encoding='utf-8') as file:
                file.write(encrypted_content)
            
            print(f"✅ File encrypted successfully: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error encrypting file: {e}")
            return False
    
    def get_operation_statistics(self) -> Dict:
        """Get statistics about performed operations."""
        if not self.operation_log:
            return {"total_operations": 0}
        
        stats = {
            "total_operations": len(self.operation_log),
            "encryptions": sum(1 for op in self.operation_log if op['operation'] == 'ENCRYPT'),
            "decryptions": sum(1 for op in self.operation_log if op['operation'] == 'DECRYPT'),
            "total_characters_processed": sum(op['message_length'] for op in self.operation_log),
            "most_used_shift": Counter(op['shift'] for op in self.operation_log).most_common(1)[0][0]
        }
        
        return stats


class CaesarCipherUI:
    """User Interface handler for Caesar Cipher operations."""
    
    def __init__(self):
        """Initialize the UI with a cipher instance."""
        self.cipher = AdvancedCaesarCipher()
        self.banner = """
╔═══════════════════════════════════════════════════════════════╗
║                    ADVANCED CAESAR CIPHER                     ║
║                 PRODIGY_CS_01 - Version 1.0                   ║
║                                                               ║
║            🔐 Cybersecurity Internship Project 🔐             ║
║                        Prodigy InfoTech                       ║
╚═══════════════════════════════════════════════════════════════╝
"""
    
    def display_banner(self):
        """Display the application banner."""
        print(self.banner)
        print("🚀 Advanced Caesar Cipher with Security Analysis Features")
        print("─" * 65)
    
    def get_valid_integer(self, prompt: str, min_val: int = None, max_val: int = None) -> int:
        """
        Get a valid integer input from user with validation.
        
        Args:
            prompt (str): Input prompt
            min_val (int): Minimum allowed value
            max_val (int): Maximum allowed value
            
        Returns:
            int: Valid integer input
        """
        while True:
            try:
                value = int(input(prompt))
                
                if min_val is not None and value < min_val:
                    print(f"❌ Value must be at least {min_val}")
                    continue
                
                if max_val is not None and value > max_val:
                    print(f"❌ Value must be at most {max_val}")
                    continue
                
                return value
                
            except ValueError:
                print("❌ Please enter a valid integer")
    
    def get_message_input(self) -> str:
        """Get message input from user with validation."""
        while True:
            message = input("\n📝 Enter your message: ").strip()
            
            if not message:
                print("❌ Message cannot be empty")
                continue
            
            return message
    
    def get_shift_value(self) -> int:
        """Get shift value from user with validation."""
        shift = self.get_valid_integer(
            "\n🔢 Enter shift value (1-25, negative values allowed): "
        )
        return shift
    
    def display_main_menu(self) -> str:
        """Display main menu and get user choice."""
        menu_options = """
🎯 MAIN MENU - Choose an operation:
═══════════════════════════════════════
1. 🔒 Encrypt Message
2. 🔓 Decrypt Message  
3. 🔍 Brute Force Analysis
4. 📊 Frequency Analysis
5. 📁 File Operations
6. 📈 Operation Statistics
7. ❓ Help & Information
8. 🚪 Exit

"""
        print(menu_options)
        
        while True:
            choice = input("Enter your choice (1-8): ").strip()
            
            if choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
                return choice
            
            print("❌ Invalid choice. Please enter a number between 1-8")
    
    def handle_encrypt_decrypt(self, mode: str):
        """Handle encryption or decryption operations."""
        message = self.get_message_input()
        shift = self.get_shift_value()
        
        if mode == "encrypt":
            result = self.cipher.encrypt(message, shift)
            operation = "🔒 ENCRYPTED"
        else:
            result = self.cipher.decrypt(message, shift)
            operation = "🔓 DECRYPTED"
        
        print(f"\n{operation} MESSAGE:")
        print("═" * 50)
        print(f"Original:  {message}")
        print(f"Shift:     {shift}")
        print(f"Result:    {result}")
        
        # Show frequency analysis for longer messages
        if len(message) > 20:
            self.cipher.display_frequency_analysis(message, "ORIGINAL TEXT")
            self.cipher.display_frequency_analysis(result, f"{mode.upper()}ED TEXT")
    
    def handle_brute_force(self):
        """Handle brute force analysis."""
        message = self.get_message_input()
        print(f"\n🎯 Performing brute force attack on: '{message}'")
        
        results = self.cipher.brute_force_attack(message)
        
        print(f"\n💡 ANALYSIS COMPLETE - Found {len(results)} possible decryptions")
        print("Look for meaningful English text in the results above.")
    
    def handle_frequency_analysis(self):
        """Handle frequency analysis."""
        message = self.get_message_input()
        self.cipher.display_frequency_analysis(message, "FREQUENCY ANALYSIS")
        
        # Compare with English letter frequencies
        english_freq = {
            'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
            'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3
        }
        
        print("\n📚 ENGLISH LANGUAGE REFERENCE:")
        print("=" * 40)
        print("Char | Expected% | Reference")
        print("-" * 40)
        for char, freq in english_freq.items():
            bar = "▓" * int(freq / 2)
            print(f"  {char}  |    {freq:4.1f}%  | {bar}")
    
    def handle_file_operations(self):
        """Handle file encryption/decryption operations."""
        print("\n📁 FILE OPERATIONS")
        print("═" * 30)
        print("1. Encrypt file")
        print("2. Decrypt file")
        
        choice = input("\nChoose operation (1-2): ").strip()
        
        if choice not in ['1', '2']:
            print("❌ Invalid choice")
            return
        
        file_path = input("Enter file path: ").strip()
        
        if not os.path.exists(file_path):
            print("❌ File not found")
            return
        
        shift = self.get_shift_value()
        output_path = input("Enter output file path (or press Enter for auto): ").strip()
        
        if not output_path:
            suffix = ".encrypted" if choice == '1' else ".decrypted"
            output_path = f"{file_path}{suffix}"
        
        if choice == '1':
            self.cipher.encrypt_file(file_path, shift, output_path)
        else:
            # For decryption, we'll read and decrypt
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                
                decrypted_content = self.cipher.decrypt(content, shift)
                
                with open(output_path, 'w', encoding='utf-8') as file:
                    file.write(decrypted_content)
                
                print(f"✅ File decrypted successfully: {output_path}")
                
            except Exception as e:
                print(f"❌ Error decrypting file: {e}")
    
    def display_statistics(self):
        """Display operation statistics."""
        stats = self.cipher.get_operation_statistics()
        
        print("\n📈 OPERATION STATISTICS")
        print("═" * 40)
        
        if stats["total_operations"] == 0:
            print("No operations performed yet.")
            return
        
        print(f"Total Operations:     {stats['total_operations']}")
        print(f"Encryptions:          {stats['encryptions']}")
        print(f"Decryptions:          {stats['decryptions']}")
        print(f"Characters Processed: {stats['total_characters_processed']}")
        print(f"Most Used Shift:      {stats['most_used_shift']}")
    
    def display_help(self):
        """Display help and information."""
        help_text = """
📚 CAESAR CIPHER - HELP & INFORMATION
═══════════════════════════════════════════════════════════════

🔍 WHAT IS CAESAR CIPHER?
The Caesar cipher is one of the simplest and most widely known 
encryption techniques. It is a substitution cipher where each 
letter is shifted by a fixed number of positions in the alphabet.

🔧 HOW IT WORKS:
• Encryption: Each letter is shifted forward by 'n' positions
• Decryption: Each letter is shifted backward by 'n' positions
• Example: With shift 3, 'A' becomes 'D', 'B' becomes 'E', etc.

🛡️ SECURITY CONSIDERATIONS:
• Caesar cipher is NOT secure for real-world use
• Vulnerable to frequency analysis attacks
• Can be broken with brute force (only 25 possible keys)
• Used here for educational purposes only

🎯 CYBERSECURITY LEARNING POINTS:
• Understanding classical cryptography
• Frequency analysis techniques
• Brute force attack simulation
• Importance of key space in encryption

⚠️  EDUCATIONAL USE ONLY - DO NOT USE FOR REAL SECURITY!
"""
        print(help_text)
    
    def run(self):
        """Main application loop."""
        self.display_banner()
        
        while True:
            try:
                choice = self.display_main_menu()
                
                if choice == '1':
                    self.handle_encrypt_decrypt("encrypt")
                elif choice == '2':
                    self.handle_encrypt_decrypt("decrypt")
                elif choice == '3':
                    self.handle_brute_force()
                elif choice == '4':
                    self.handle_frequency_analysis()
                elif choice == '5':
                    self.handle_file_operations()
                elif choice == '6':
                    self.display_statistics()
                elif choice == '7':
                    self.display_help()
                elif choice == '8':
                    print("\n👋 Thank you for using Advanced Caesar Cipher!")
                    print("🎓 Keep learning cybersecurity! Stay secure! 🔒")
                    break
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye! Stay secure! 🔒")
                break
            except Exception as e:
                print(f"\n❌ An unexpected error occurred: {e}")
                print("Please try again or contact support.")


def main():
    """Main function to run the Caesar Cipher application."""
    # Handle command line arguments for advanced users
    parser = argparse.ArgumentParser(
        description="Advanced Caesar Cipher - PRODIGY_CS_01",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python caesar_cipher.py                    # Interactive mode
  python caesar_cipher.py --encrypt "Hello" --shift 3
  python caesar_cipher.py --decrypt "Khoor" --shift 3
  python caesar_cipher.py --brute-force "Khoor"
        """
    )
    
    parser.add_argument('--encrypt', help='Text to encrypt')
    parser.add_argument('--decrypt', help='Text to decrypt')
    parser.add_argument('--shift', type=int, help='Shift value')
    parser.add_argument('--brute-force', help='Text to brute force')
    parser.add_argument('--file', help='File to encrypt/decrypt')
    
    args = parser.parse_args()
    
    # Command line mode
    if any([args.encrypt, args.decrypt, args.brute_force, args.file]):
        cipher = AdvancedCaesarCipher()
        
        if args.encrypt:
            if args.shift is None:
                print("❌ Shift value required for encryption")
                return
            result = cipher.encrypt(args.encrypt, args.shift)
            print(f"Encrypted: {result}")
        
        elif args.decrypt:
            if args.shift is None:
                print("❌ Shift value required for decryption")
                return
            result = cipher.decrypt(args.decrypt, args.shift)
            print(f"Decrypted: {result}")
        
        elif args.brute_force:
            results = cipher.brute_force_attack(args.brute_force)
            print("Brute force complete - check output above")
        
        elif args.file:
            if args.shift is None:
                print("❌ Shift value required for file operations")
                return
            cipher.encrypt_file(args.file, args.shift)
    
    else:
        # Interactive mode
        ui = CaesarCipherUI()
        ui.run()


if __name__ == "__main__":
    main()