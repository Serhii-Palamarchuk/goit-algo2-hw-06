import hashlib


class BloomFilter:
    """
    Реалізація фільтра Блума для ефективної перевірки наявності елементів
    з мінімальним використанням пам'яті.
    """

    def __init__(self, size: int, num_hashes: int):
        """
        Ініціалізація фільтра Блума.

        Args:
            size: Розмір бітового масиву
            num_hashes: Кількість хеш-функцій
        """
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [0] * size

    def _hash(self, item: str, seed: int) -> int:
        """
        Генерує хеш для елемента з використанням seed.

        Args:
            item: Елемент для хешування
            seed: Зерно для хеш-функції

        Returns:
            Позиція в бітовому масиві
        """
        # Використовуємо SHA256 з seed для генерації різних хешів
        hash_obj = hashlib.sha256(f"{item}{seed}".encode("utf-8"))
        return int(hash_obj.hexdigest(), 16) % self.size

    def add(self, item: str) -> None:
        """
        Додає елемент до фільтра Блума.

        Args:
            item: Елемент для додавання
        """
        if not isinstance(item, str):
            item = str(item)

        # Встановлюємо біти для всіх хеш-функцій
        for i in range(self.num_hashes):
            position = self._hash(item, i)
            self.bit_array[position] = 1

    def contains(self, item: str) -> bool:
        """
        Перевіряє, чи може елемент бути у фільтрі.

        Args:
            item: Елемент для перевірки

        Returns:
            True якщо елемент можливо є у фільтрі, False якщо точно немає
        """
        if not isinstance(item, str):
            item = str(item)

        # Перевіряємо всі біти для всіх хеш-функцій
        for i in range(self.num_hashes):
            position = self._hash(item, i)
            if self.bit_array[position] == 0:
                return False
        return True


def check_password_uniqueness(bloom: BloomFilter, passwords: list) -> dict:
    """
    Перевіряє список паролів на унікальність використовуючи фільтр Блума.

    Args:
        bloom: Екземпляр BloomFilter з вже доданими паролями
        passwords: Список паролів для перевірки

    Returns:
        Словник з паролями та їх статусом (унікальний/вже використаний)
    """
    results = {}

    for password in passwords:
        # Обробка порожніх або некоректних значень
        if password is None or (isinstance(password, str) and not password.strip()):
            results[str(password)] = "некоректний пароль"
            continue

        # Перетворюємо на рядок якщо потрібно
        password_str = str(password) if not isinstance(password, str) else password

        # Перевіряємо наявність у фільтрі
        if bloom.contains(password_str):
            results[password_str] = "вже використаний"
        else:
            results[password_str] = "унікальний"

    return results


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")
