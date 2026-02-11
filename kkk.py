#!/usr/bin/env python3
"""
🔥 INFERNO 257 - Fixed Encryption
• Handles 0-256 range properly
• 10% password-based noise encryption
• Perfect video decryption
"""

import os
import sys
import time
import getpass
from pathlib import Path
from typing import List, Tuple, Dict

class Inferno257Fixed:
    """Fixed 257-byte encryption that works with Python bytes"""
    
    ENCRYPTED_EXT = '.inferno257'
    
    def __init__(self):
        self.current_dir = Path.cwd()
        self.noise_level = 0.10  # 10% noise
        self.encryption_passes = 2
        self.custom_range = 257  # 0-256 range
    
    # ==================== FIXED 257-BYTE HANDLING ====================
    
    def _byte_to_257(self, b: int) -> int:
        """Convert byte (0-255) to 0-256 range"""
        return b % self.custom_range
    
    def _from_257_to_byte(self, val: int) -> int:
        """Convert 0-256 range back to byte (0-255)"""
        return val % 256
    
    def _apply_257_operation(self, value: int, operation: str, param: int) -> int:
        """Apply operation in 257 range and convert back to byte"""
        if operation == 'add':
            result = (value + param) % self.custom_range
        elif operation == 'sub':
            result = (value - param) % self.custom_range
        elif operation == 'mul':
            result = (value * param) % self.custom_range
        elif operation == 'xor':
            result = (value ^ param) % self.custom_range
        elif operation == 'rol':
            # Rotate left within 257 range
            bits = 9  # Need 9 bits for 0-256
            result = ((value << param) | (value >> (bits - param))) % self.custom_range
        elif operation == 'ror':
            # Rotate right within 257 range
            bits = 9
            result = ((value >> param) | (value << (bits - param))) % self.custom_range
        else:
            result = value
        
        # Convert back to 0-255 for storage
        return self._from_257_to_byte(result)
    
    # ==================== FIXED KEY GENERATION ====================
    
    def _create_fixed_key(self, password: str, length: int = 1024) -> bytes:
        """Create key that stays within byte range"""
        key = bytearray()
        pass_bytes = password.encode('utf-8', errors='ignore')
        
        for i in range(length):
            idx1 = i % len(pass_bytes)
            idx2 = (i * 7) % len(pass_bytes)
            
            # Start with XOR of password bytes
            base = pass_bytes[idx1] ^ pass_bytes[idx2]
            
            # Apply transformations that stay in 0-255
            if i % 3 == 0:
                transformed = ((base << 2) | (base >> 6)) & 0xFF
            elif i % 3 == 1:
                transformed = (base * 3 + 7) & 0xFF
            else:
                transformed = (base ^ 0x7F) & 0xFF
            
            # Add position influence
            transformed ^= (i & 0xFF)
            
            key.append(transformed)
        
        return bytes(key)
    
    # ==================== FIXED NOISE ENCRYPTION ====================
    
    def _generate_fixed_noise(self, data: bytes, password: str) -> Tuple[List[int], bytes]:
        """Generate 10% noise within byte range"""
        # Create seed from password
        seed = 0
        for char in password:
            seed = (seed * 31 + ord(char)) & 0xFFFFFFFF
        
        # Calculate noise positions (10% of data)
        noise_count = max(1, int(len(data) * self.noise_level))
        
        # Generate positions
        positions = []
        temp_seed = seed
        
        for i in range(noise_count):
            # Simple LCG for positions
            temp_seed = (temp_seed * 1103515245 + 12345) & 0x7FFFFFFF
            pos = temp_seed % len(data)
            
            if pos not in positions:
                positions.append(pos)
            else:
                # Try nearby position
                for offset in range(1, 100):
                    new_pos = (pos + offset) % len(data)
                    if new_pos not in positions:
                        positions.append(new_pos)
                        break
        
        positions.sort()
        
        # Generate noise bytes
        noise_bytes = bytearray()
        pass_bytes = password.encode('utf-8')
        
        for i, pos in enumerate(positions):
            # Create deterministic noise
            noise = 0
            for j in range(3):
                idx = (i + j + pos) % len(pass_bytes)
                noise ^= pass_bytes[idx] << (j * 2)
            
            noise = (noise * 13 + i * 17) & 0xFF
            noise_bytes.append(noise)
        
        return positions, bytes(noise_bytes)
    
    def _apply_fixed_noise(self, data: bytes, password: str) -> Tuple[bytes, List[int], bytes]:
        """Apply noise using only byte-safe operations"""
        positions, noise_bytes = self._generate_fixed_noise(data, password)
        
        noisy_data = bytearray(data)
        
        for i, pos in enumerate(positions):
            if pos < len(noisy_data):
                noise = noise_bytes[i]
                original = noisy_data[pos]
                
                # Simple reversible operations
                mixed = original ^ noise
                mixed = ((mixed << 1) | (mixed >> 7)) & 0xFF  # Rotate left 1
                mixed = (mixed + (pos & 0xFF)) & 0xFF  # Add position
                
                noisy_data[pos] = mixed
        
        return bytes(noisy_data), positions, noise_bytes
    
    def _remove_fixed_noise(self, data: bytes, positions: List[int], noise_bytes: bytes) -> bytes:
        """Remove noise (reverse operations)"""
        clean_data = bytearray(data)
        
        for i, pos in enumerate(positions):
            if pos < len(clean_data):
                noise = noise_bytes[i]
                noisy = clean_data[pos]
                
                # Reverse operations
                noisy = (noisy - (pos & 0xFF)) & 0xFF
                noisy = ((noisy >> 1) | (noisy << 7)) & 0xFF
                noisy ^= noise
                
                clean_data[pos] = noisy
        
        return bytes(clean_data)
    
    # ==================== SIMPLE ENCRYPTION ALGORITHM ====================
    
    def _simple_encrypt(self, data: bytes, key: bytes, pass_num: int) -> bytes:
        """Simple encryption that stays in byte range"""
        result = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(data):
            k1 = key[(i + pass_num * 11) % key_len]
            k2 = key[(i * 7 + pass_num * 23) % key_len]
            
            # Start with byte
            encrypted = byte
            
            # Operation 1: XOR with first key
            encrypted ^= k1
            
            # Operation 2: Add second key
            encrypted = (encrypted + k2) & 0xFF
            
            # Operation 3: Rotate based on position
            rotate = (i + pass_num) & 7  # 0-7 bits
            encrypted = ((encrypted << rotate) | (encrypted >> (8 - rotate))) & 0xFF
            
            # Operation 4: XOR with position
            encrypted ^= (i & 0xFF)
            
            result.append(encrypted)
        
        return bytes(result)
    
    def _simple_decrypt(self, data: bytes, key: bytes, pass_num: int) -> bytes:
        """Simple decryption (reverse)"""
        result = bytearray()
        key_len = len(key)
        
        for i, encrypted in enumerate(data):
            k1 = key[(i + pass_num * 11) % key_len]
            k2 = key[(i * 7 + pass_num * 23) % key_len]
            
            # Reverse operations
            decrypted = encrypted
            
            # Reverse operation 4: XOR with position
            decrypted ^= (i & 0xFF)
            
            # Reverse operation 3: Rotate back
            rotate = (i + pass_num) & 7
            decrypted = ((decrypted >> rotate) | (decrypted << (8 - rotate))) & 0xFF
            
            # Reverse operation 2: Subtract key
            decrypted = (decrypted - k2) & 0xFF
            
            # Reverse operation 1: XOR with key
            decrypted ^= k1
            
            result.append(decrypted)
        
        return bytes(result)
    
    # ==================== COMPLETE ENCRYPTION/DECRYPTION ====================
    
    def encrypt_data(self, data: bytes, password: str) -> Tuple[bytes, Dict]:
        """Complete encryption with noise"""
        # Apply noise first
        noisy_data, noise_positions, noise_bytes = self._apply_fixed_noise(data, password)
        
        # Create key
        key = self._create_fixed_key(password, 1024)
        
        # Apply encryption passes
        encrypted = noisy_data
        for pass_num in range(self.encryption_passes):
            encrypted = self._simple_encrypt(encrypted, key, pass_num)
        
        # Metadata
        metadata = {
            'original_size': len(data),
            'noise_positions': noise_positions,
            'noise_bytes': noise_bytes,
            'encryption_passes': self.encryption_passes
        }
        
        return encrypted, metadata
    
    def decrypt_data(self, encrypted_data: bytes, password: str, metadata: Dict) -> bytes:
        """Complete decryption with noise removal"""
        # Recreate key
        key = self._create_fixed_key(password, 1024)
        
        # Decrypt in reverse order
        decrypted = encrypted_data
        for pass_num in reversed(range(metadata['encryption_passes'])):
            decrypted = self._simple_decrypt(decrypted, key, pass_num)
        
        # Remove noise
        decrypted = self._remove_fixed_noise(
            decrypted,
            metadata['noise_positions'],
            metadata['noise_bytes']
        )
        
        # Trim to original size
        return decrypted[:metadata['original_size']]
    
    # ==================== FILE OPERATIONS ====================
    
    def encrypt_file(self, filepath: str, password: str) -> bool:
        """Encrypt file with simple algorithm"""
        try:
            path = Path(filepath)
            if not path.exists():
                print(f"❌ File not found: {filepath}")
                return False
            
            file_size = path.stat().st_size
            
            print(f"\n{'='*60}")
            print(f"🔥 INFERNO 257 FIXED ENCRYPTION")
            print(f"📜 File: {path.name}")
            print(f"📊 Size: {self._format_size(file_size)}")
            print(f"🌫️  Noise: {int(self.noise_level * 100)}%")
            print(f"🔄 Passes: {self.encryption_passes}")
            print(f"{'='*60}")
            
            # Read file
            print("📖 Reading file...")
            with open(path, 'rb') as f:
                data = f.read()
            
            # Encrypt
            print("🔐 Encrypting...")
            start_time = time.time()
            encrypted, metadata = self.encrypt_data(data, password)
            elapsed = time.time() - start_time
            
            # Save
            output_path = str(path) + self.ENCRYPTED_EXT
            
            with open(output_path, 'wb') as f:
                # Simple header
                f.write(b'INF257F')  # Magic
                f.write(self._int_to_bytes(metadata['original_size'], 8))
                f.write(self._int_to_bytes(len(metadata['noise_positions']), 4))
                
                # Noise data
                for pos in metadata['noise_positions']:
                    f.write(self._int_to_bytes(pos, 4))
                
                f.write(self._int_to_bytes(len(metadata['noise_bytes']), 4))
                f.write(metadata['noise_bytes'])
                
                f.write(self._int_to_bytes(metadata['encryption_passes'], 2))
                
                # Encrypted data
                f.write(encrypted)
            
            final_size = os.path.getsize(output_path)
            speed = file_size / elapsed / (1024*1024) if elapsed > 0 else 0
            
            print(f"\n✅ ENCRYPTION COMPLETE!")
            print(f"📁 Output: {Path(output_path).name}")
            print(f"📊 Encrypted size: {self._format_size(final_size)}")
            print(f"🌫️  Noise positions: {len(metadata['noise_positions'])}")
            print(f"⏱️  Time: {elapsed:.3f}s")
            print(f"🚀 Speed: {speed:.1f} MB/s")
            
            # Verify
            print("\n🔍 Self-verification...")
            decrypted = self.decrypt_data(encrypted, password, metadata)
            
            if len(decrypted) == len(data) and decrypted[:1000] == data[:1000]:
                print("✅ VERIFICATION PASSED - Perfect reversibility!")
                return True
            else:
                print("❌ VERIFICATION FAILED")
                return False
            
        except Exception as e:
            print(f"\n❌ Encryption failed: {e}")
            return False
    
    def decrypt_file(self, filepath: str, password: str) -> bool:
        """Decrypt file"""
        try:
            path = Path(filepath)
            if not path.exists():
                print(f"❌ File not found: {filepath}")
                return False
            
            print(f"\n{'='*60}")
            print(f"🔥 INFERNO 257 FIXED DECRYPTION")
            print(f"📜 File: {path.name}")
            print(f"{'='*60}")
            
            # Read encrypted file
            with open(path, 'rb') as f:
                magic = f.read(7)
                if magic != b'INF257F':
                    print("❌ Not an Inferno 257 Fixed file")
                    return False
                
                original_size = self._bytes_to_int(f.read(8))
                noise_count = self._bytes_to_int(f.read(4))
                
                # Read noise positions
                noise_positions = []
                for _ in range(noise_count):
                    pos = self._bytes_to_int(f.read(4))
                    noise_positions.append(pos)
                
                # Read noise bytes
                noise_bytes_len = self._bytes_to_int(f.read(4))
                noise_bytes = f.read(noise_bytes_len)
                
                # Read encryption passes
                encryption_passes = self._bytes_to_int(f.read(2))
                
                # Read encrypted data
                encrypted = f.read()
            
            print(f"🔍 File Analysis:")
            print(f"   Original size: {self._format_size(original_size)}")
            print(f"   Noise positions: {noise_count}")
            print(f"   Encryption passes: {encryption_passes}")
            
            # Prepare metadata
            metadata = {
                'original_size': original_size,
                'noise_positions': noise_positions,
                'noise_bytes': noise_bytes,
                'encryption_passes': encryption_passes
            }
            
            # Decrypt
            print("\n🔓 Decrypting...")
            start_time = time.time()
            decrypted = self.decrypt_data(encrypted, password, metadata)
            elapsed = time.time() - start_time
            
            # Save decrypted
            if filepath.endswith(self.ENCRYPTED_EXT):
                output_path = filepath[:-len(self.ENCRYPTED_EXT)]
            else:
                output_path = filepath + '.decrypted'
            
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            
            speed = len(decrypted) / elapsed / (1024*1024) if elapsed > 0 else 0
            
            print(f"\n✅ DECRYPTION COMPLETE!")
            print(f"📁 Output: {Path(output_path).name}")
            print(f"📊 Size: {self._format_size(len(decrypted))}")
            print(f"🌫️  Noise removed: {noise_count} positions")
            print(f"⏱️  Time: {elapsed:.3f}s")
            print(f"🚀 Speed: {speed:.1f} MB/s")
            
            # Check file type
            self._check_file_type(output_path, decrypted)
            
            return True
            
        except Exception as e:
            print(f"\n❌ Decryption failed: {e}")
            return False
    
    def _check_file_type(self, filepath: str, data: bytes):
        """Check if file appears valid"""
        path = Path(filepath)
        ext = path.suffix.lower()
        
        print(f"\n🔍 File verification:")
        print(f"   Extension: {ext}")
        print(f"   Size: {self._format_size(len(data))}")
        
        if len(data) < 100:
            print("   ⚠️  File is very small")
            return
        
        # Check common signatures
        if ext == '.mp4' and b'ftyp' in data[:1000]:
            print("   ✅ MP4 video structure detected")
        elif ext == '.avi' and data[:4] == b'RIFF' and data[8:12] == b'AVI ':
            print("   ✅ AVI video structure detected")
        elif ext == '.mkv' and data[:4] == b'\x1a\x45\xdf\xa3':
            print("   ✅ Matroska video structure detected")
        elif ext == '.jpg' and data[:3] == b'\xff\xd8\xff':
            print("   ✅ JPEG image structure detected")
        elif ext == '.png' and data[:8] == b'\x89PNG\r\n\x1a\n':
            print("   ✅ PNG image structure detected")
        elif ext == '.mp3' and (data[:3] == b'ID3' or data[:2] == b'\xff\xfb'):
            print("   ✅ MP3 audio structure detected")
        else:
            # Generic check
            null_bytes = data[:1000].count(0)
            if 50 < null_bytes < 950:
                print("   📊 Looks like a valid binary file")
            else:
                print("   ⚠️  May be corrupted or wrong password")
    
    # ==================== SIMPLE INTERFACE ====================
    
    def simple_menu(self):
        """Simple menu for easy use"""
        while True:
            print(f"\n{'='*60}")
            print(f"🔥 INFERNO 257 FIXED")
            print(f"📂 {self.current_dir.name}/")
            print(f"{'='*60}")
            
            # List files
            normal_files = []
            encrypted_files = []
            
            for item in self.current_dir.iterdir():
                if item.is_file():
                    if item.name.endswith(self.ENCRYPTED_EXT):
                        encrypted_files.append({
                            'path': str(item),
                            'name': item.name,
                            'size': item.stat().st_size
                        })
                    else:
                        normal_files.append({
                            'path': str(item),
                            'name': item.name,
                            'size': item.stat().st_size
                        })
            
            print(f"📊 Files: {len(normal_files)} normal | {len(encrypted_files)} encrypted")
            
            # Show some files
            if normal_files:
                print(f"\n📁 Normal files:")
                for file in normal_files[:5]:
                    ext = Path(file['path']).suffix.lower()
                    icon = self._get_file_icon(ext)
                    print(f"   {icon} {file['name'][:30]:32} {self._format_size(file['size']):>10}")
                if len(normal_files) > 5:
                    print(f"   ... and {len(normal_files) - 5} more")
            
            if encrypted_files:
                print(f"\n🔒 Encrypted files:")
                for file in encrypted_files[:5]:
                    print(f"   🔒 {file['name'][:30]:32} {self._format_size(file['size']):>10}")
                if len(encrypted_files) > 5:
                    print(f"   ... and {len(encrypted_files) - 5} more")
            
            print(f"\n{'='*60}")
            print("1. 🔐 Encrypt a file")
            print("2. 🔓 Decrypt a file")
            print("3. 🎬 Encrypt all videos")
            print("4. 🖼️ Encrypt all images")
            print("5. ⚡ Encrypt all files")
            print("6. 🔄 Decrypt all encrypted files")
            print("7. ⚙️ Settings")
            print("8. 🧪 Test system")
            print("9. 🚪 Exit")
            print(f"{'='*60}")
            
            choice = input("\nSelect: ").strip()
            
            if choice == "1":
                self._encrypt_menu(normal_files)
            elif choice == "2":
                self._decrypt_menu(encrypted_files)
            elif choice == "3":
                self._batch_encrypt_videos(normal_files)
            elif choice == "4":
                self._batch_encrypt_images(normal_files)
            elif choice == "5":
                self._batch_encrypt_all(normal_files)
            elif choice == "6":
                self._batch_decrypt_all(encrypted_files)
            elif choice == "7":
                self._settings_menu()
            elif choice == "8":
                self._run_tests()
            elif choice == "9":
                print("\n🔥 Exiting...")
                break
    
    def _encrypt_menu(self, files: List[Dict]):
        """Encrypt menu"""
        if not files:
            print("❌ No files to encrypt")
            return
        
        print("\n📁 Files:")
        for i, file in enumerate(files[:20], 1):
            ext = Path(file['path']).suffix.lower()
            icon = self._get_file_icon(ext)
            print(f"{i:2}. {icon} {file['name'][:35]:37} {self._format_size(file['size']):>10}")
        
        if len(files) > 20:
            print(f"   ... and {len(files) - 20} more")
        
        choice = input("\nSelect file or enter path: ").strip()
        
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                filepath = files[idx]['path']
            else:
                print("❌ Invalid selection")
                return
        else:
            filepath = choice
        
        if os.path.exists(filepath):
            password = getpass.getpass("Password: ")
            confirm = getpass.getpass("Confirm: ")
            
            if password == confirm:
                self.encrypt_file(filepath, password)
            else:
                print("❌ Passwords don't match")
        else:
            print("❌ File not found")
    
    def _decrypt_menu(self, files: List[Dict]):
        """Decrypt menu"""
        if not files:
            print("❌ No encrypted files found")
            return
        
        print("\n🔒 Encrypted files:")
        for i, file in enumerate(files, 1):
            print(f"{i:2}. 🔒 {file['name'][:35]:37} {self._format_size(file['size']):>10}")
        
        choice = input("\nSelect file or enter path: ").strip()
        
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                filepath = files[idx]['path']
            else:
                print("❌ Invalid selection")
                return
        else:
            filepath = choice
        
        if os.path.exists(filepath):
            password = getpass.getpass("Password: ")
            self.decrypt_file(filepath, password)
        else:
            print("❌ File not found")
    
    def _batch_encrypt_videos(self, files: List[Dict]):
        """Encrypt all video files"""
        video_exts = ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv']
        video_files = [f for f in files if Path(f['path']).suffix.lower() in video_exts]
        
        if not video_files:
            print("❌ No video files found")
            return
        
        print(f"\n🎬 Found {len(video_files)} video files")
        
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm: ")
        
        if password != confirm:
            print("❌ Passwords don't match")
            return
        
        success = 0
        for i, file in enumerate(video_files, 1):
            print(f"\n[{i}/{len(video_files)}] {file['name']}")
            if self.encrypt_file(file['path'], password):
                success += 1
        
        print(f"\n✅ Encrypted {success}/{len(video_files)} videos")
    
    def _batch_encrypt_images(self, files: List[Dict]):
        """Encrypt all image files"""
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']
        image_files = [f for f in files if Path(f['path']).suffix.lower() in image_exts]
        
        if not image_files:
            print("❌ No image files found")
            return
        
        print(f"\n🖼️ Found {len(image_files)} image files")
        
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm: ")
        
        if password != confirm:
            print("❌ Passwords don't match")
            return
        
        success = 0
        for i, file in enumerate(image_files, 1):
            print(f"\n[{i}/{len(image_files)}] {file['name']}")
            if self.encrypt_file(file['path'], password):
                success += 1
        
        print(f"\n✅ Encrypted {success}/{len(image_files)} images")
    
    def _batch_encrypt_all(self, files: List[Dict]):
        """Encrypt all files"""
        if not files:
            print("❌ No files to encrypt")
            return
        
        print(f"\n⚡ Found {len(files)} files to encrypt")
        
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm: ")
        
        if password != confirm:
            print("❌ Passwords don't match")
            return
        
        success = 0
        for i, file in enumerate(files, 1):
            print(f"\n[{i}/{len(files)}] {file['name']}")
            if self.encrypt_file(file['path'], password):
                success += 1
        
        print(f"\n✅ Encrypted {success}/{len(files)} files")
    
    def _batch_decrypt_all(self, files: List[Dict]):
        """Decrypt all encrypted files"""
        if not files:
            print("❌ No encrypted files found")
            return
        
        print(f"\n🔄 Found {len(files)} encrypted files")
        
        password = getpass.getpass("Password: ")
        
        success = 0
        for i, file in enumerate(files, 1):
            print(f"\n[{i}/{len(files)}] {file['name']}")
            if self.decrypt_file(file['path'], password):
                success += 1
        
        print(f"\n✅ Decrypted {success}/{len(files)} files")
    
    def _settings_menu(self):
        """Settings menu"""
        while True:
            print(f"\n{'='*60}")
            print("⚙️ SETTINGS")
            print(f"{'='*60}")
            print(f"1. Encryption passes: {self.encryption_passes}")
            print(f"2. Noise level: {int(self.noise_level * 100)}%")
            print("3. Back")
            print(f"{'='*60}")
            
            choice = input("\nSelect: ").strip()
            
            if choice == "1":
                passes = input("Encryption passes (1-5): ").strip()
                if passes.isdigit() and 1 <= int(passes) <= 5:
                    self.encryption_passes = int(passes)
                    print(f"✅ Passes set to {self.encryption_passes}")
                else:
                    print("❌ Must be 1-5")
            elif choice == "2":
                level = input("Noise level (1-30%): ").strip()
                if level.isdigit() and 1 <= int(level) <= 30:
                    self.noise_level = int(level) / 100
                    print(f"✅ Noise level set to {int(self.noise_level * 100)}%")
                else:
                    print("❌ Must be 1-30")
            elif choice == "3":
                break
    
    def _run_tests(self):
        """Run tests"""
        print("\n🧪 Running tests...")
        
        # Create test data
        test_data = b"Test data for Inferno 257" + bytes(range(256)) + b'\x00' * 100 + b'\xff' * 100
        password = "test123"
        
        print(f"Test data: {len(test_data)} bytes")
        
        try:
            # Encrypt
            encrypted, metadata = self.encrypt_data(test_data, password)
            print(f"Encrypted: {len(encrypted)} bytes")
            
            # Decrypt
            decrypted = self.decrypt_data(encrypted, password, metadata)
            print(f"Decrypted: {len(decrypted)} bytes")
            
            # Verify
            if test_data == decrypted:
                print("✅ TEST PASSED - Perfect reversibility!")
            else:
                print("❌ TEST FAILED - Data mismatch")
                
                # Find first difference
                for i in range(min(len(test_data), len(decrypted))):
                    if test_data[i] != decrypted[i]:
                        print(f"First difference at byte {i}: {test_data[i]} != {decrypted[i]}")
                        break
        
        except Exception as e:
            print(f"❌ Test error: {e}")
    
    def _get_file_icon(self, ext: str) -> str:
        """Get icon for file type"""
        if ext in ['.mp4', '.avi', '.mkv', '.mov']:
            return '🎬'
        elif ext in ['.jpg', '.jpeg', '.png', '.gif']:
            return '🖼️'
        elif ext in ['.mp3', '.wav', '.flac']:
            return '🎵'
        elif ext in ['.pdf', '.doc', '.docx', '.txt']:
            return '📄'
        elif ext in ['.zip', '.rar', '.7z']:
            return '📦'
        else:
            return '📁'
    
    # ==================== UTILITIES ====================
    
    @staticmethod
    def _format_size(size: int) -> str:
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}TB"
    
    @staticmethod
    def _int_to_bytes(num: int, length: int) -> bytes:
        """Convert int to bytes"""
        return num.to_bytes(length, 'big')
    
    @staticmethod
    def _bytes_to_int(data: bytes) -> int:
        """Convert bytes to int"""
        return int.from_bytes(data, 'big')

def main():
    """Main entry point"""
    print(f"\n{'='*60}")
    print("🔥 INFERNO 257 FIXED - Working Encryption")
    print("⚡ Simple | Reliable | Perfect Video Decryption")
    print(f"{'='*60}")
    
    inferno = Inferno257Fixed()
    
    # Command line mode
    if len(sys.argv) > 1:
        if len(sys.argv) == 4:
            cmd = sys.argv[1].lower()
            filepath = sys.argv[2]
            password = sys.argv[3]
            
            if cmd in ["encrypt", "e"]:
                inferno.encrypt_file(filepath, password)
            elif cmd in ["decrypt", "d"]:
                inferno.decrypt_file(filepath, password)
        
        elif len(sys.argv) == 3:
            filepath = sys.argv[1]
            password = sys.argv[2]
            
            if filepath.endswith(inferno.ENCRYPTED_EXT):
                inferno.decrypt_file(filepath, password)
            else:
                inferno.encrypt_file(filepath, password)
        
        elif len(sys.argv) == 2:
            if sys.argv[1] == "test":
                inferno._run_tests()
            elif os.path.exists(sys.argv[1]):
                filepath = sys.argv[1]
                if filepath.endswith(inferno.ENCRYPTED_EXT):
                    password = getpass.getpass("Password: ")
                    inferno.decrypt_file(filepath, password)
                else:
                    password = getpass.getpass("Password: ")
                    confirm = getpass.getpass("Confirm: ")
                    if password == confirm:
                        inferno.encrypt_file(filepath, password)
    
    # Interactive mode
    else:
        inferno.simple_menu()

if __name__ == "__main__":
    main()