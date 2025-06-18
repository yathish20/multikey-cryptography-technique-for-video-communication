from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

def generate_key_pair(private_key_path="private-key.pem", public_key_path="public-key.pem"):
    """
    Generate RSA key pair and save them to files
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Save private key
    with open(private_key_path, 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save public key
    with open(public_key_path, 'wb') as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    
    print(f"Keys generated successfully!")
    print(f"Private key saved to: {os.path.abspath(private_key_path)}")
    print(f"Public key saved to: {os.path.abspath(public_key_path)}")

def verify_keys(private_key_path="private-key.pem", public_key_path="public-key.pem"):
    """
    Verify that the keys are valid and properly formatted
    """
    try:
        # Read and load private key
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Read and load public key
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        print("Keys verified successfully!")
        return True
        
    except Exception as e:
        print(f"Error verifying keys: {str(e)}")
        return False

if __name__ == "__main__":
    # Generate new key pair
    generate_key_pair()
    
    # Verify the generated keys
    verify_keys()