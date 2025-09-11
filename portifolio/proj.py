import json
import os
import getpass
from cryptography.fernet import Fernet
import hashlib

class PasswordManager:
    """
    Classe para gerenciar senhas de forma segura, utilizando criptografia.
    """
    def __init__(self):
        """
        Inicializa o gerenciador, carregando a chave de criptografia
        e o banco de dados de senhas.
        """
        self.key_file = "secret.key"
        self.passwords_file = "passwords.json"
        
        self.key = self._load_key()
        self.fernet = Fernet(self.key)
        self.passwords = self._load_passwords()
        
    def _load_key(self):
        """
        Carrega a chave de criptografia do arquivo 'secret.key'.
        Se o arquivo não existir, uma nova chave é gerada e salva.
        Retorna a chave.
        """
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
            return key

    def _load_passwords(self):
        """
        Carrega as senhas do arquivo 'passwords.json'.
        Se o arquivo não existir ou estiver vazio, retorna um dicionário vazio.
        Retorna o dicionário de senhas.
        """
        if os.path.exists(self.passwords_file) and os.path.getsize(self.passwords_file) > 0:
            try:
                with open(self.passwords_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                return {}
        else:
            return {}

    def _save_passwords(self):
        """
        Salva o dicionário de senhas criptografadas no arquivo 'passwords.json'.
        """
        with open(self.passwords_file, "w") as f:
            json.dump(self.passwords, f, indent=4)
            
    def _hash_password(self, password):
        """
        Cria um hash da senha mestra usando SHA256 para não armazenar
        a senha em texto puro.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def add_password(self, service, pwd):
        """
        Adiciona uma nova senha para um serviço, criptografando-a antes de salvar.
        """
        encrypted_pwd = self.fernet.encrypt(pwd.encode()).decode()
        self.passwords[service] = encrypted_pwd
        self._save_passwords()
        print(f"Senha para '{service}' adicionada com sucesso!")

    def get_password(self, service):
        """
        Recupera e decifra a senha de um serviço.
        Retorna a senha decifrada ou None se o serviço não for encontrado.
        """
        if service in self.passwords:
            encrypted_pwd = self.passwords[service].encode()
            decrypted_pwd = self.fernet.decrypt(encrypted_pwd).decode()
            return decrypted_pwd
        return None

    def list_services(self):
        """
        Lista todos os serviços para os quais há senhas cadastradas.
        """
        if not self.passwords:
            print("Nenhum serviço cadastrado.")
        else:
            print("Serviços cadastrados:")
            for service in self.passwords.keys():
                print(f"- {service}")

    def remove_password(self, service):
        """
        Remove uma senha de um serviço específico.
        """
        if service in self.passwords:
            del self.passwords[service]
            self._save_passwords()
            print(f"Senha para '{service}' removida.")
        else:
            print(f"Serviço '{service}' não encontrado.")

def main():
    """
    Função principal que gerencia o fluxo de execução do programa.
    """
    
    # 1. Autenticação da senha mestra
    master_password_hash_file = "master_hash.txt"
    
    # Verifica se o arquivo de hash da senha mestra existe
    if not os.path.exists(master_password_hash_file):
        print("Bem-vindo! Parece que é a primeira vez que você executa o programa.")
        new_master_password = getpass.getpass("Crie sua senha mestra: ")
        master_hash = hashlib.sha256(new_master_password.encode()).hexdigest()
        with open(master_password_hash_file, "w") as f:
            f.write(master_hash)
        print("Senha mestra criada com sucesso!")
        
    # Agora que o arquivo existe, podemos tentar a autenticação
    attempts = 3
    while attempts > 0:
        entered_password = getpass.getpass("Digite a senha mestra para continuar: ")
        entered_hash = hashlib.sha256(entered_password.encode()).hexdigest()
        
        with open(master_password_hash_file, "r") as f:
            master_hash_stored = f.read()

        if entered_hash == master_hash_stored:
            print("Acesso concedido!")
            break
        else:
            attempts -= 1
            print(f"Senha incorreta. Você tem mais {attempts} tentativa(s).")
    
    if attempts == 0:
        print("Número máximo de tentativas excedido. Saindo...")
        return
        
    # 2. Inicialização e Loop Principal
    manager = PasswordManager()

    while True:
        print("\n--- Gerenciador de Senhas ---")
        print("1. Adicionar senha")
        print("2. Recuperar senha")
        print("3. Listar serviços")
        print("4. Remover senha")
        print("5. Sair")

        choice = input("Escolha uma opção: ")

        if choice == "1":
            service = input("Nome do serviço: ")
            pwd = getpass.getpass("Senha: ")
            manager.add_password(service, pwd)
        
        elif choice == "2":
            service = input("Nome do serviço: ")
            pwd = manager.get_password(service)
            if pwd:
                print(f"Senha para '{service}': {pwd}")
            else:
                print(f"Serviço '{service}' não encontrado.")
        
        elif choice == "3":
            manager.list_services()
        
        elif choice == "4":
            service = input("Nome do serviço para remover: ")
            manager.remove_password(service)
        
        elif choice == "5":
            print("Saindo do programa...")
            break
        
        else:
            print("Opção inválida. Por favor, tente novamente.")

if __name__ == "__main__":
    main()