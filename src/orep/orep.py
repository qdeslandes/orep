"""Orep's library.

Provides interface to manipulate hosts' credentials and 1Password Connect REST API.

Attributes:
    DEFAULT_KEY_LEN (int): default length for SSH RSA keys.
"""

import enum
import io
import json
import logging
import os
import re
import secrets
import select
import socket
import subprocess
import sys
import termios
import time
import tty
import typing
import paramiko
import onepasswordconnectsdk as op

DEFAULT_KEY_LEN = 4096


def channel_wait_for(channel: paramiko.channel.Channel, endswith: typing.Pattern, timeout: int = 5):
    """Wait on Paramiko channel for a matching string on stdout.

    Args:
        channel (paramiko.channel.Channel): Paramiko channel to read from.
        endswith (typing.Pattern): regex to match to channel's stdout, in UTF-8.
        timeout (int): timeout in seconds to wait for data on stdout.
    """

    timeout += time.time()

    read_buffer = ""
    while not re.search(endswith, read_buffer):
        if channel.recv_ready():
            read_buffer += channel.recv(4096).decode("utf-8")
        elif time.time() > timeout:
            raise TimeoutError(f"Timeout while waiting for '{endswith}' on the channel")
        else:
            time.sleep(0.1)


def generate_random_string(length: int = 32):
    """Generate a random fixed-length string.

    Args:
        length (int): length of the string to generate.

    Returns:
        str: random string.
    """
    return secrets.token_urlsafe(length)


class OpConnect(op.client.Client):
    """1Password Connect client.

    Allows for querying 1Password Connect server. Provides all methods defined in 1Password's
    original SDK, with some extra conveniance methods.

    Args:
        host (str): 1Password Connect SDK host.
        api_key (str): 1Password Connect API key.
        logger (logging.Logger): logging object to write logs to.
    """

    def __init__(self, host: str, api_key: str, logger: logging.Logger = logging):
        self._host = host
        self._api_key = api_key
        self._logger = logger
        super().__init__(url=self._host, token=self._api_key)

        self._logger.info(f"Create OpConnect object to {self._host}")

    def get_vault_by_name(self, name: str):
        """Find a specific vault using its name.

        As 1Password's original SDK doesn't provide any way to find a specific vault using its name,
        here is the implementation. We need to first get all the vault available, then search for
        the one matching the given name.

        Args:
            name (str): name of the vault to find.

        Returns:
            op.models.Vault: vault if found, or None.
        """

        for vault in self.get_vaults():
            if vault.name == name:
                return vault

        return None

    def get_items_by_name(self, vault: op.models.Vault, name: str):
        """Retrieves all items matching a specific name.

        Get all items from 1Passwords storage matching the given name. As 1Password doesn't require
        names to be unique, with method provides a convenient way to get all items for a given name.

        Args:
            vault (op.models.Vault): vault to find items in.
            name (str): name of the items to return.

        Returns:
            list[op.models.Item]: all items in the vault matching the given name.
        """

        return [item for item in self.get_items(vault.id) if item.title == name]


class CredentialsType(enum.Enum):
    """SSH credentials types.

    Attributes:
        SSH_KEY (int): SSH key credentials.
        PASSWORD (int): password credentials.
    """

    SSH_KEY = 1
    PASSWORD = 2


class HostCredentials:
    """Stores, backup, and generate credentials for a given host.

    Credentials are managed and generated using Paramiko. We use RSA SSH keys with fixed size key
    (see DEFAULT_KEY_LEN). Password and SSH key can be automatically generated and updated on the
    remote host.

    Args:
        hostname (str): hostname (or IP address) of the remote host. The credentials will be stored
            in 1Password under this name. So if you use IP address, it will be the title of the
            1Password entry.
        opconnect (OpConnect): 1Password connect client.
        vault (op.models.Vault): vault the credentials should be found/saved to.
        logger (logging.Logger): logging object to write logs to.

    Attributes:
        hostname (str): hostname (or IP address) of the remote host.
        username (str): remote user's name.
        password (str): remote user's password.
        private_key (paramiko.rsakey.RSAKey): private key used to connect to the remote host for
            this specific user.
        private_key_passphrase (str): passphrase used to encrypt the private key.
        public_key (str): public key associated to the private key.
        exists (bool): true of the credential exists in 1Password, false otherwise.
    """

    def __init__(
        self,
        hostname: str,
        opconnect: OpConnect,
        vault: op.models.Vault,
        logger: logging.Logger = logging,
    ):
        # Credentials
        self._hostname = hostname
        self._username = None
        self._password = None
        self._private_key = None
        self._private_key_passphrase = None

        # 1Password API
        self._id = None
        self._op = opconnect
        self._vault = vault

        # Logging
        self._logger = logger
        self._logger.debug(f"Create Host object for '{hostname}'")

        self._load()

    def _private_key_to_string(self) -> str:
        """Return the private key as a string.

        If a passphrase is defined for the private key, the returned key will be encrypted with
        it.

        Returns:
            str: private key as string, if it exists. None otherwise.
        """

        if not self._private_key:
            return None

        private_key = io.StringIO()
        self._private_key.write_private_key(private_key, password=self._private_key_passphrase)

        return private_key.getvalue()

    def _load(self):
        """Load the crendentials from 1Password if they exists.

        If the credentials can be found in 1Password using the given hostname, they are loaded
        in the object. If more than 1 items are found with the given hostname, then none of them
        are loaded and an exception is thrown. Credentials **must** be unique.
        """

        # Find existing credentials for given hostname.
        items = self._op.get_items_by_name(self._vault, self._hostname)
        if not items:
            self._logger.warning(f"Host '{self.hostname}' does not exists (yet)")
            return
        elif len(items) > 1:
            msg = f"{len(items)} credentials found for {self.hostname}. Aborting."
            self._logger.fatal(msg)
            raise Exception(msg)

        # Get item's content if found.
        item = self._op.get_item(items[0].id, self._vault.id)
        self._id = item.id
        for field in item.fields:
            if field.label == "username":
                self._username = field.value
            elif field.label == "password":
                self._password = field.value
            elif field.label == "private key":
                private_key = field.value
            elif field.label == "private key passphrase":
                private_key_passphrase = field.value

        if private_key:
            self._private_key = paramiko.RSAKey.from_private_key(
                io.StringIO(private_key), password=private_key_passphrase
            )
            self._private_key_passphrase = private_key_passphrase

        self._logger.info("Loaded credentials from 1Password!")

    def _save(self):
        """Save credentials to 1Password.

        Prepare all field with proper section and type (especially for sensitive data, as the fields
        must be concealed) then send them to 1Password Connect server to save them.
        """

        section = op.models.Section(id=generate_random_string(), label="SSH")

        # Prepare fields
        fields = []
        if self._username:
            fields += [op.models.Field(label="username", value=self._username, purpose="USERNAME")]
        if self._password:
            fields += [op.models.Field(label="password", value=self._password, purpose="PASSWORD")]
        if self._private_key:
            fields += [
                op.models.Field(
                    label="private key",
                    value=self._private_key_to_string(),
                    type="CONCEALED",
                    section=section,
                )
            ]
            if self._private_key_passphrase:
                fields += [
                    op.models.Field(
                        label="private key passphrase",
                        value=self._private_key_passphrase,
                        type="CONCEALED",
                        section=section,
                    )
                ]
            fields += [op.models.Field(label="public key", value=self.public_key, section=section)]

        # Save to 1Password
        new_item = self._op.create_item(
            self._vault.id,
            op.models.Item(
                vault=self._vault,
                title=self.hostname,
                category="LOGIN",
                tags=["device/host", "ssh"],
                sections=[section],
                fields=fields,
            ),
        )
        self._id = new_item.id

        self._logger.info(f"Saved credentials for {self.hostname}")

    def _connect(
        self, using: CredentialsType = CredentialsType.SSH_KEY, password: str = None
    ) -> paramiko.SSHClient:
        """Connect to remote host using either password or SSH key.

        Connect to the remote host using predefined credentials. If the host's key is missing, it
        will be automatically added.

        Notes:
            - This method *will* throw if credentials are invalid!
            - Port 22 will be used (hardcoded).

        Args:
            using (CredentialsType): type of credentials to use (SSH key or password).
            password (str): password to use, if CredentialsType.PASSWORD is used.

        Returns:
            paramiko.SSHClient: SSH client, connected to remote host.
        """

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if using == CredentialsType.SSH_KEY:
            self._logger.info(f"Logging to '{self.hostname}' using SSH key")
            client.connect(self._hostname, port=22, username=self._username, pkey=self._private_key)
        else:
            self._logger.info(f"Logging to '{self.hostname}' using password")
            client.connect(self.hostname, port=22, username=self.username, password=password)

        return client

    def _gen_password(self, length: int = 32):
        """Generate new fixed-length password for the remote host.

        New password will be randomly generated. This method won't update the remote host.

        Args:
            length (str): length of the password.
        """

        self._password = generate_random_string(length)

    def _gen_ssh_key(self, passphrase_length: int = 32):
        """Generate a new SSH key for the remote host.

        New SSH key will be randomly generated. This method won't update the remote host.

        Args:
            passphrase_length (str): length of the key's passphrase.
        """

        self._private_key_passphrase = generate_random_string(passphrase_length)
        self._private_key = paramiko.RSAKey.generate(DEFAULT_KEY_LEN)

    def _update_password_on_remote(self, client: paramiko.SSHClient, current_password: str):
        """Update password on remote host.

        From a connected SSH client, this method will use `passwd` to update the user's password
        on the host.

        Args:
            client (paramiko.SSHClient): client connected to the remote host.
            current_password (str): current remote host's password, which will be updated.
        """

        channel = client.invoke_shell()
        channel.send("passwd\n")
        channel_wait_for(channel, ".*Current password:.*")
        channel.send(f"{current_password}\n")
        channel_wait_for(channel, ".*New password:.*")
        channel.send(f"{self.password}\n")
        channel_wait_for(channel, ".*Retype new password:.*")
        channel.send(f"{self.password}\n")
        channel_wait_for(channel, ".*all authentication tokens updated successfully.*")
        self._logger.info("Password successfully updated on remote host!")

    def _copy_key_on_remote(self, client: paramiko.SSHClient):
        """Update SSH key on the remote host.

        From a connected SSH client, this method will add the current SSH public key to the list of
        authorized keys for the current user.

        Args:
            client (paramiko.SSHClient): client connected to the remote host.

        Todo:
            - Remote existing SSH public key. When the key is renewed, the previous public key is
                not removed from authorized key.
        """

        client.exec_command("mkdir -p ~/.ssh/")
        client.exec_command(f'echo "{self.public_key}" > ~/.ssh/authorized_keys')
        client.exec_command("chmod 644 ~/.ssh/authorized_keys")
        client.exec_command("chmod 700 ~/.ssh/")
        self._logger.info("SSH key successfully copied to remote host!")

    def create(self, username: str, current_password: str, force: bool = False):
        """Create new credentials for current host and save them to 1Password.

        This method will generate new password and SSH key, then exported them to the remote host
        before saving them to 1Password.
        If credentials already exists, nothing will be done.

        Be careful, if credentials already exists and `force` is True, previous password and SSH key
        will be discarded, you could be locked out of the remote host! If valid credentials already
        exists, use `renew` instead.

        Args:
            username (str): usernrame to update the credentials for.
            current_password (str): current user's password. Used to log to the host to be able
                to update the credentials.
            force (bool): if True, forces credentials update, even if they already exists.
        """

        # Check if credentials already exist in 1Password
        if self._id:
            if not force:
                self._logger.error(f"Credentials for {self.hostname} already exists.")
                return
            else:
                self._logger.info(
                    "Forcing credentials creation: existing credentials will be removed!"
                )

        self._username = username

        # Generate new credentials
        self._gen_password()
        self._gen_ssh_key()

        # Update host with new credentials
        client = self._connect(CredentialsType.PASSWORD, password=current_password)
        self._update_password_on_remote(client, current_password)
        self._copy_key_on_remote(client)
        client.close()

        # Save credentials
        if self._id:
            self._op.delete_item(self._id, self._vault.id)
        self._save()

    def renew(self):
        """Update credentials for a existing host.

        Current credentials will be changed, and remote host will be updated.
        """

        # Check if credentials already exist in 1Password
        if not self._id:
            self._logger.error("Credentials doesn't exist yet!")
            return

        self.create(self.username, self.password, force=True)

    def connect(self):
        """Create interactive shell on the remote host.

        Opens a PTY on a remote server, and allows interactive commands to be run. Reassigns stdin
        to the PTY so that is functions like a full shell, as would be given by the OpenSSH client.

        Differences between the behavior of OpenSSH and the Paramiko connection can cause mysterious
        errors, especially with respect to authentication. By keeping the entire SSH2 connection
        within Paramiko, such inconsistencies are eliminated.
        """

        def resize_pty():
            tty_height, tty_width = subprocess.check_output(["stty", "size"]).split()
            try:
                channel.resize_pty(width=int(tty_width), height=int(tty_height))
            except paramiko.ssh_exception.SSHException:
                pass

        client = self._connect(CredentialsType.SSH_KEY)

        # Get the current TTY attributes to reapply after the remote shell is closed.
        oldtty_attrs = termios.tcgetattr(sys.stdin)
        channel = client.invoke_shell()
        try:
            stdin_fileno = sys.stdin.fileno()
            tty.setraw(stdin_fileno)
            tty.setcbreak(stdin_fileno)
            channel.settimeout(0.0)
            is_alive = True

            while is_alive:
                resize_pty()

                # Block until the remote shell and stdin are ready for reading.
                read_ready, _, _ = select.select([channel, sys.stdin], [], [])

                # If the channel is one of the ready objects, print it out 1024 chars at a time.
                if channel in read_ready:
                    try:
                        out = channel.recv(1024)

                        # If remote closed.
                        if len(out) == 0:
                            is_alive = False
                        else:
                            print(out.decode("utf-8"), end="")
                            sys.stdout.flush()
                    except socket.timeout:
                        pass

                if sys.stdin in read_ready and is_alive:
                    # Send a single character out at a time as human input would.
                    # Use an os.read to prevent nasty buffering problem with shell history.
                    char = os.read(stdin_fileno, 1)

                    # If this side of the connection closes, shut down gracefully.
                    if len(char) == 0:
                        is_alive = False
                    else:
                        channel.send(char)

            # Close down the channel for send/recv. This is an explicit call most likely redundant
            # with the operations that caused an exit from the REPL, but unusual exit conditions
            # can cause this to be reached uncalled.
            channel.shutdown(2)
        # Regardless of errors, restore the TTY to working order upon exit.
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSAFLUSH, oldtty_attrs)
            self._logger.info(f"Connection to {self.hostname} closed.")

        client.close()

    @property
    def hostname(self) -> str:
        """Remote host's hostname or IP address.

        Returns:
            str: remote host's hostname or IP address.
        """
        return self._hostname

    @property
    def username(self) -> str:
        """Remote user's name.

        Returns:
            str: current remote user's username.
        """
        return self._username

    @property
    def password(self) -> str:
        """Remote user's password.

        Returns:
            str: current remote user's password.
        """
        return self._password

    @property
    def private_key(self) -> paramiko.rsakey.RSAKey:
        """Remote user's SSH private key.

        Returns:
            paramiko.rsakey.RSAKey: SSH private key.
        """
        return self._private_key

    @property
    def private_key_passphrase(self) -> str:
        """Remote user's SSH private key's passphrase.

        Returns:
            str: SSH private key's passphrase.
        """
        return self._private_key_passphrase

    @property
    def public_key(self) -> str:
        """Remote user's SSH public key.

        Returns:
            str: SSH public key, prefixed with 'ssh-rsa' so it is valid.
        """
        return f"ssh-rsa {self._private_key.get_base64()}"

    @property
    def exists(self) -> bool:
        """Check if credentials already exists.

        Returns:
            bool: True if credentials exists in 1Password, false otherwise.
        """
        return self._id is not None
