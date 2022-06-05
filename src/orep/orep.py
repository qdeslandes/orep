"""Orep's library.

Provides interface to manipulate hosts' credentials and 1Password Connect REST API.

Attributes:
    DEFAULT_KEY_LEN (int): default length for SSH RSA keys.
    SUDO_REGEXP (re.Pattern): compiled regexp used to detect interactive sudo password request.
    DEFAULT_SSH_USER_TAG (str): 1Password tag used to mark default SSH user for a given host.
    _LOGGER (logging.Logger): logging object to use.

Todo:
    - Allow `su` command during interactive SSH sessions.
"""

import enum
import io
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
SUDO_REGEXP = re.compile(r"\[sudo\] password for .*:")
DEFAULT_SSH_USER_TAG = "orep_default_ssh_user"

_LOGGER = logging


def set_logger(logger: logging.Logger):
    """Set default logger for orep.

    Args:
        logger (logging.Logger): logger object to use as default.
    """

    global _LOGGER
    _LOGGER = logger


def private_key_to_string(private_key: paramiko.rsakey.RSAKey, private_key_passphrase: str) -> str:
    """Return the private key as a string.

    If a passphrase is defined for the private key, the returned key will be encrypted with
    it.

    Args:
        private_key (paramiko.rsakey.RASKey): SSH private key to convert to a string.
        private_key_passphrase (str): passphrase used to encrypt the private key.

    Returns:
        str: private key as string, if it exists. None otherwise.
    """

    private_key_str = io.StringIO()
    private_key.write_private_key(private_key_str, password=private_key_passphrase)

    return private_key_str.getvalue()


def connect_to(hostname: str, username: str, secret) -> paramiko.SSHClient:
    """Connect to remote host using either password or SSH key.

    Connect to the remote host using predefined credentials. If the host's key is missing, it
    will be automatically added. Depending the type of `secret`, the client will connect with the
    user's password or its private key.

    Notes:
        - This method *will* throw if credentials are invalid!
        - Port 22 will be used (hardcoded).

    Args:
        hostname (str): remote hostname (or FQDN) to connect to.
        username (str): SSH username to connect as.
        secret (any): password (str) or private key (paramiko.rsakey.RSAKey) to use to connect to
            the remote host.

    Returns:
        paramiko.SSHClient: SSH client, connected to remote host.
    """

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if type(secret) is paramiko.rsakey.RSAKey:
        _LOGGER.info(f"Logging to '{hostname}' using SSH key")
        client.connect(hostname, port=22, username=username, pkey=secret)
    elif type(secret) is str:
        _LOGGER.info(f"Logging to '{hostname}' using password")
        client.connect(hostname, port=22, username=username, password=secret)
    else:
        raise Exception(f"Unsupported secret type for: {secret}")

    return client


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


def update_remote_password(client: paramiko.SSHClient, username: str, from_pwd: str, to_pwd: str):
    """Update password on remote host.

    From a connected SSH client, this method will use `passwd` to update the user's password
    on the host.
    `passwd` command won't ask for the current password if the user calling the command is root,
    in which case we skip this step.

    Args:
        client (paramiko.SSHClient): client connected to the remote host.
        username (str): SSH username to connect as.
        from_pwd (str): old password to use.
        to_pwd (str): new password for the given user.
    """

    channel = client.invoke_shell()
    channel.send("passwd\n")
    if username != "root":
        channel_wait_for(channel, ".*Current password:.*")
        channel.send(f"{from_pwd}\n")
    channel_wait_for(channel, ".*New password:.*")
    channel.send(f"{to_pwd}\n")
    channel_wait_for(channel, ".*Retype new password:.*")
    channel.send(f"{to_pwd}\n")
    channel_wait_for(channel, ".*successfully.*")
    _LOGGER.info("Password successfully updated on remote host!")


def copy_remote_key(client: paramiko.SSHClient, public_key: str):
    """Update SSH key on the remote host.

    From a connected SSH client, this method will add the given SSH public key to the list of
    authorized keys for the connect user.
    The connected user must have a home folder already created, otherwise this function will fail.

    Args:
        client (paramiko.SSHClient): client connected to the remote host.
        public_key (str): public key to copy to `authorized_keys` file.

    Todo:
        - Remove existing SSH public key. When the key is renewed, the previous public key is
            not removed from authorized key.
    """

    client.exec_command("mkdir -p ~/.ssh/")
    client.exec_command(f'echo "{public_key}" > ~/.ssh/authorized_keys')
    client.exec_command("chmod 644 ~/.ssh/authorized_keys")
    client.exec_command("chmod 700 ~/.ssh/")
    _LOGGER.info("SSH key successfully copied to remote host!")


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


class User:
    """User object.

    Store a user's credentials and settings on the remote host.

    Args:
        id (str): user's ID in 1Password. If no ID is defined, it means the user isn't yet backed-up
            in 1Password.
        username (str): username on the remote host.
        password (str): user's password.
        private_key (paramiko.rsakey.RSAKey): user's private key.
        private_key_passphrase (str): password use to encrypt the private key.
        is_default (bool): if True, this used it the default user to connect as. Only one default
            user is allowed for each host.
    """

    def __init__(
        self,
        id: str = None,
        username: str = None,
        password: str = None,
        private_key: paramiko.rsakey.RSAKey = None,
        private_key_passphrase: str = None,
        is_default: bool = False,
    ):
        self._id = id
        self._username = username
        self._password = password
        self._private_key = private_key
        self._private_key_passphrase = private_key_passphrase
        self._is_default = is_default

    def gen_password(self, length: int = 32):
        """Generate new fixed-length password for the remote host.

        New password will be randomly generated. This method won't update the remote host.

        Args:
            length (str): length of the password.
        """

        self._password = generate_random_string(length)

    def gen_ssh_key(self, passphrase_length: int = 32):
        """Generate a new SSH key for the remote host.

        New SSH key will be randomly generated. This method won't update the remote host.

        Args:
            passphrase_length (str): length of the key's passphrase.
        """

        self._private_key_passphrase = generate_random_string(passphrase_length)
        self._private_key = paramiko.RSAKey.generate(DEFAULT_KEY_LEN)

    @property
    def id(self) -> str:
        """User's ID in 1Password.

        Returns:
            str: user's ID in 1Password
        """

        return self._id

    @id.setter
    def id(self, id: str):
        """Set user's ID in 1Password.

        This is only required when loading the user from 1Password database.

        Args:
            id: user's ID in 1Password.
        """

        self._id = id

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
    def is_default(self) -> bool:
        """Check if the user is the default user on its host.

        Returns:
            bool: True if the user is the default user to use, False otherwise.
        """

        return self._is_default

    @is_default.setter
    def is_default(self, is_default):
        """Change user's default status.

        If True, this user is the one used when connecting to its host without any specified user.

        Args:
            is_default: True if the user should be the default one, False otherwise.
        """

        self._is_default = is_default

    @property
    def exists(self) -> bool:
        """Check if the user exists in 1Password database.

        Returns:
            bool: True if the user exists in 1Password database, False otherwise.
        """

        return self._id != None


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
        self._users = {}

        # 1Password API
        self._op = opconnect
        self._vault = vault

        self._load()

    def _load(self):
        """Load the crendentials from 1Password if they exists.

        All credentials in 1Password matching the given hostname are loaded.
        """

        # Find existing credentials for given hostname.
        items = self._op.get_items_by_name(self._vault, self._hostname)
        if not items:
            self._logger.warning(f"Host '{self.hostname}' does not exists (yet)")
            return

        # Get item's content if found.
        for item in items:
            user = self._op.get_item(item.id, self._vault.id)
            self._id = item.id
            fields = {field.label: field.value for field in user.fields}

            private_key = None
            if "private key" in fields:
                private_key = paramiko.RSAKey.from_private_key(
                    io.StringIO(fields["private key"]), password=fields["private key passphrase"]
                )

            self._users[fields["username"]] = User(
                user.id,
                fields["username"],
                fields["password"],
                private_key,
                fields["private key passphrase"] if private_key else None,
                DEFAULT_SSH_USER_TAG in user.tags,
            )

        _LOGGER.info(f"Loaded credentials: {', '.join(self._users.keys())}")

    def _save(self, user: User):
        """Save credentials to 1Password.

        Prepare all field with proper section and type (especially for sensitive data, as the fields
        must be concealed) then send them to 1Password Connect server to save them.
        If the given user is already present in 1Password database, it will be updated, so its ID
        won't be changed.

        Args:
            user: user to save to 1Password.
        """

        section = op.models.Section(id=generate_random_string(), label="SSH")

        # Prepare fields
        fields = [
            op.models.Field(label="username", value=user.username, purpose="USERNAME"),
            op.models.Field(label="password", value=user.password, purpose="PASSWORD"),
        ]

        if user.private_key:
            fields += [
                op.models.Field(
                    label="private key",
                    value=private_key_to_string(user.private_key, user.private_key_passphrase),
                    type="CONCEALED",
                    section=section,
                ),
                op.models.Field(
                    label="private key passphrase",
                    value=user.private_key_passphrase,
                    type="CONCEALED",
                    section=section,
                ),
                op.models.Field(label="public key", value=user.public_key, section=section),
            ]

        # Save to 1Password
        tags = ["device/system", "ssh"]
        tags += [DEFAULT_SSH_USER_TAG] if user.is_default else []

        item = op.models.Item(
            id=user.id,
            vault=self._vault,
            title=self.hostname,
            tags=tags,
            category="LOGIN",
            sections=[section],
            fields=fields,
        )

        if user.exists:
            self._op.update_item(user.id, self._vault.id, item)
            _LOGGER.info(f"Updated credentials for {user.username}")
        else:
            new_item = self._op.create_item(self._vault.id, item)
            user.id = new_item.id
            _LOGGER.info(f"Saved credentials for {user.username}")

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
        if username in self._users.keys():
            if not force:
                _LOGGER.error(f"Credentials for {username} on {self.hostname} already exists.")
                return
            else:
                _LOGGER.info("Forcing credentials creation: existing credentials will be removed!")

        user = self._users.get(username, User(username=username))
        user.gen_password()
        user.gen_ssh_key()

        # Update host with new credentials
        client = connect_to(self.hostname, user.username, current_password)
        update_remote_password(client, user.username, current_password, user.password)
        copy_remote_key(client, user.public_key)
        client.close()

        # Save credentials
        self._save(user)

    def renew(self, username: str):
        """Update credentials for a existing host.

        Current credentials will be changed, and remote host will be updated.

        Args:
            username: username for which credentials have to be renewed.
        """

        # Check if credentials already exist in 1Password
        user = self._users.get(username, None)
        if not user:
            self._logger.error(f"Credentials for {username} on {self.hostname} doesn't exist yet!")
            return

        self.create(user.username, user.password, force=True)

    def default(self, username: str):
        """Set default user for the remote host.

        Default user is the one is used to connect to the remote host if no user is passed.

        Args:
            username: remote user to connect as. If None, then the default user is used (if
                it exists).
        """

        new_default = self._users.get(username, None)
        if not new_default:
            raise Exception(f"Can't set {username} as default user: user does not exists!")

        prev_default = self.default_user
        if prev_default and prev_default.id == new_default.id:
            _LOGGER.info(f"{username} is already the default user, skipping.")
            return

        if prev_default:
            prev_default.is_default = False
            self._save(prev_default)

        new_default.is_default = True
        self._save(new_default)
        _LOGGER.info(f"Set {username} as default user for {self.hostname}")

    def connect(self, username: str):
        """Create interactive shell on the remote host.

        Opens a PTY on a remote server, and allows interactive commands to be run. Reassigns stdin
        to the PTY so that is functions like a full shell, as would be given by the OpenSSH client.

        Differences between the behavior of OpenSSH and the Paramiko connection can cause mysterious
        errors, especially with respect to authentication. By keeping the entire SSH2 connection
        within Paramiko, such inconsistencies are eliminated.

        Args:
            username: user to connect as. Must be a valid user (with credentials stored in
                1Password).
        """

        def resize_pty():
            tty_height, tty_width = subprocess.check_output(["stty", "size"]).split()
            try:
                channel.resize_pty(width=int(tty_width), height=int(tty_height))
            except paramiko.ssh_exception.SSHException:
                pass

        user = self._users.get(username) if username else self.default_user
        if username and not user:
            raise Exception(f"No credentials found for {username} on {self.hostname}!")
        elif not user:
            raise Exception(f"No default user defined for {self.hostname}!")

        client = connect_to(self.hostname, user.username, user.private_key)

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
                            msg = out.decode("utf-8")
                            print(msg, end="")

                            if SUDO_REGEXP.match(msg):
                                channel.send(f"{user.password}\n")

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
    def default_user(self) -> User:
        """Get the host's default user.

        If no default user is defined for the host, then None is returned. If multiple default
        users are found, an exception is returned.

        Returns:
            User: default user, or not if not found.
        """

        default_users = [user for user in self._users.values() if user.is_default]
        if len(default_users) == 0:
            return None
        elif len(default_users) > 1:
            raise Exception(f"{len(default_users)} found, this is not expected!")

        return default_users[0]

    @property
    def hostname(self) -> str:
        """Remote host's hostname or IP address.

        Returns:
            str: remote host's hostname or IP address.
        """
        return self._hostname
