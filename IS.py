import streamlit as st
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os
from io import BytesIO


KEY_LENGTH = 24  
SALT = b"$ez*&214097GDAKACNASC;LSOSSBAdjskasnmosuf!@#$^()_adsa"  


def encryptor(image_data, password):
    try:
      
        padded_data = pad(image_data, DES.block_size)

     
        hash_original = SHA256.new(data=image_data)

        
        key = PBKDF2(password, SALT, dkLen=KEY_LENGTH)


        iv1 = os.urandom(8)  
        iv2 = os.urandom(8) 
        iv3 = os.urandom(8)  

        cipher1 = DES.new(key[:8], DES.MODE_CBC, iv1)
        cipher2 = DES.new(key[8:16], DES.MODE_CBC, iv2)
        cipher3 = DES.new(key[16:], DES.MODE_CBC, iv3)

       
        encrypted_data = cipher3.encrypt(
            cipher2.decrypt(
                cipher1.encrypt(padded_data)
            )
        )

        
        encrypted_data_with_iv = iv1 + iv2 + iv3 + hash_original.digest() + encrypted_data

        return encrypted_data_with_iv, None
    except Exception as e:
        return None, f"Encryption failed: {str(e)}"


def decryptor(encrypted_data_with_iv, password):
    try:
      
        iv1, iv2, iv3 = encrypted_data_with_iv[:8], encrypted_data_with_iv[8:16], encrypted_data_with_iv[16:24]
        extracted_hash = encrypted_data_with_iv[24:56]
        encrypted_data = encrypted_data_with_iv[56:]

    
        key = PBKDF2(password, SALT, dkLen=KEY_LENGTH)

       
        cipher1 = DES.new(key[:8], DES.MODE_CBC, iv1)
        cipher2 = DES.new(key[8:16], DES.MODE_CBC, iv2)
        cipher3 = DES.new(key[16:], DES.MODE_CBC, iv3)

       
        decrypted_data = cipher1.decrypt(
            cipher2.encrypt(
                cipher3.decrypt(encrypted_data)
            )
        )

       
        decrypted_data = unpad(decrypted_data, DES.block_size)

        
        hash_decrypted = SHA256.new(data=decrypted_data)
        if hash_decrypted.digest() == extracted_hash:
            return decrypted_data, None
        else:
            return None, "Decryption failed. Incorrect password or data corruption."

    except Exception as e:
        return None, f"Decryption failed: {str(e)}"


def main():
    st.title("Image Encryption and Decryption using 3DES")
    
    
    option = st.selectbox("Choose an option", ["Encrypt Image", "Decrypt Image"])
    
    if option == "Encrypt Image":
        uploaded_file = st.file_uploader("Upload an image to encrypt", type=["jpg", "png", "jpeg"])
        
        if uploaded_file is not None:
            image_data = uploaded_file.read()

            
            password = st.text_input("Enter password for encryption", type="password")
            
            if st.button("Encrypt"):
                if len(password) < 8:
                    st.error("Password must be at least 8 characters long.")
                else:
                    encrypted_data, error = encryptor(image_data, password)
                    if error:
                        st.error(error)
                    else:
                      
                        st.success("Encryption successful!")
                        st.download_button(
                            label="Download Encrypted Image",
                            data=encrypted_data,
                            file_name="encrypted_image.enc",
                            mime="application/octet-stream"
                        )
    
    elif option == "Decrypt Image":
        encrypted_file = st.file_uploader("Upload an encrypted image", type=["enc"])

        if encrypted_file is not None:
            encrypted_data_with_iv = encrypted_file.read()

            
            password = st.text_input("Enter password for decryption", type="password")
            
            if st.button("Decrypt"):
                if len(password) < 8:
                    st.error("Password must be at least 8 characters long.")
                else:
                    decrypted_data, error = decryptor(encrypted_data_with_iv, password)
                    if error:
                        st.error(error)
                    else:
                        st.success("Decryption successful!")
                        
                        st.image(decrypted_data)
  
if __name__ == "__main__":
    main()