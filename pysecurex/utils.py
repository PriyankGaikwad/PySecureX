from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from getpass import getpass

def process_data_multithreaded(func, data_list, key, *args, num_threads=None):
    """
    Process data using multithreading.

    Args:
        func: Function to be applied to each data item.
        data_list (list): List of data to process.
        key (bytes): Encryption key.
        *args: Additional arguments to pass to the function.
        num_threads (int): Number of threads to use. Defaults to None.

    Returns:
        list: Processed data.
    """
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        return list(executor.map(lambda data: func(data, key, *args), data_list))

def process_data_multiprocessing(func, data_list, key, *args, num_cpus=None):
    """
    Process data using multiprocessing.

    Args:
        func: Function to be applied to each data item.
        data_list (list): List of data to process.
        key (bytes): Encryption key.
        *args: Additional arguments to pass to the function.
        num_cpus (int): Number of CPUs to use. Defaults to None.

    Returns:
        list: Processed data.
    """
    def process_item(data):
        return func(data, key, *args)
    
    with ProcessPoolExecutor(max_workers=num_cpus) as executor:
        return list(executor.map(process_item, data_list))

def process_data(func, data_list, key, *args, method=None, num_workers=None):
    """
    Process data using the specified method (multithreading or multiprocessing).

    Args:
        func: Function to be applied to each data item.
        data_list (list): List of data to process.
        key (bytes): Encryption key.
        *args: Additional arguments to pass to the function.
        method (str): Method to use ('threading' or 'multiprocessing'). Defaults to None (single-threaded).
        num_workers (int): Number of workers (threads or CPUs) to use. Defaults to None (system default).

    Returns:
        list: Processed data.
    """
    try:
        if method == "threading":
            return process_data_multithreaded(func, data_list, key, *args, num_threads=num_workers)
        elif method == "multiprocessing":
            return process_data_multiprocessing(func, data_list, key, *args, num_cpus=num_workers)
        else:
            return [func(data, key, *args) for data in data_list]
    except Exception as e:
        raise RuntimeError(f"Error processing data: {str(e)}") from e
    
def secure_password_prompt(prompt_text: str = "Enter password: ", confirm: bool = False) -> str:
    """
    Securely prompt for a password without echoing to the screen.
    
    Args:
        prompt_text (str, optional): Text to display when prompting. Defaults to "Enter password: ".
        confirm (bool, optional): Whether to confirm the password. Defaults to False.
        
    Returns:
        str: The entered password.
        
    Example:
        >>> # This would prompt the user in an actual terminal
        >>> # password = secure_password_prompt("Enter your secure password: ", confirm=True)
    """
    password = getpass(prompt_text)
    
    if confirm:
        confirmation = getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match")
    
    return password