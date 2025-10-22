import re
import time
import hashlib
import math
import json
from typing import Set, List


class HyperLogLog:
    """
    Реалізація алгоритму HyperLogLog для наближеного підрахунку
    унікальних елементів.
    """

    def __init__(self, precision: int = 14):
        """
        Ініціалізація HyperLogLog.

        Args:
            precision: Точність (кількість бітів для індексування регістрів)
                      Типові значення: 4-16. Більше = точніше, але більше пам'яті
        """
        self.precision = precision
        self.m = 2**precision  # Кількість регістрів
        self.registers = [0] * self.m

        # Константа для корекції
        if self.m >= 128:
            self.alpha = 0.7213 / (1 + 1.079 / self.m)
        elif self.m >= 64:
            self.alpha = 0.709
        elif self.m >= 32:
            self.alpha = 0.697
        elif self.m >= 16:
            self.alpha = 0.673
        else:
            self.alpha = 0.5

    def add(self, item: str) -> None:
        """
        Додає елемент до HyperLogLog.

        Args:
            item: Елемент для додавання
        """
        # Хешуємо елемент
        hash_value = int(hashlib.sha256(item.encode("utf-8")).hexdigest(), 16)

        # Отримуємо індекс регістра (перші precision біт)
        register_index = hash_value & ((1 << self.precision) - 1)

        # Рахуємо позицію першого 1-го біта в залишку хеша
        remaining_hash = hash_value >> self.precision
        leading_zeros = self._count_leading_zeros(remaining_hash) + 1

        # Оновлюємо регістр максимальним значенням
        self.registers[register_index] = max(
            self.registers[register_index], leading_zeros
        )

    def _count_leading_zeros(self, value: int) -> int:
        """
        Підраховує кількість провідних нулів у бінарному представленні.

        Args:
            value: Число для аналізу

        Returns:
            Кількість провідних нулів
        """
        if value == 0:
            return 64  # Максимальна довжина

        leading_zeros = 0
        # Рахуємо до 64 біт
        for i in range(63, -1, -1):
            if value & (1 << i):
                break
            leading_zeros += 1
        return leading_zeros

    def count(self) -> float:
        """
        Оцінює кількість унікальних елементів.

        Returns:
            Наближена кількість унікальних елементів
        """
        # Базова оцінка
        raw_estimate = self.alpha * (self.m**2) / sum(2 ** (-x) for x in self.registers)

        # Корекція для малих значень
        if raw_estimate <= 2.5 * self.m:
            zeros = self.registers.count(0)
            if zeros != 0:
                return self.m * math.log(self.m / zeros)

        # Корекція для великих значень
        if raw_estimate <= (1 / 30) * (2**32):
            return raw_estimate
        else:
            return -(2**32) * math.log(1 - raw_estimate / (2**32))


def load_log_data(file_path: str) -> List[str]:
    """
    Завантажує IP-адреси з лог-файлу.

    Args:
        file_path: Шлях до лог-файлу

    Returns:
        Список IP-адрес
    """
    ip_addresses = []
    # Регулярний вираз для пошуку IP-адрес
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line:
                    continue

                # Спроба парсингу як JSON
                try:
                    log_entry = json.loads(line)
                    if "remote_addr" in log_entry:
                        ip = log_entry["remote_addr"]
                        # Перевірка валідності IP
                        if ip_pattern.match(ip):
                            ip_addresses.append(ip)
                        continue
                except json.JSONDecodeError:
                    pass

                # Якщо не JSON, шукаємо IP-адреси в рядку
                matches = ip_pattern.findall(line)
                if matches:
                    # Беремо першу знайдену IP-адресу
                    ip_addresses.append(matches[0])

    except FileNotFoundError:
        print(f"Файл {file_path} не знайдено!")
        return []
    except Exception as e:
        print(f"Помилка при читанні файлу: {e}")
        return []

    return ip_addresses


def exact_count(ip_addresses: List[str]) -> tuple:
    """
    Точний підрахунок унікальних IP-адрес.

    Args:
        ip_addresses: Список IP-адрес

    Returns:
        Кортеж (кількість унікальних, час виконання)
    """
    start_time = time.time()
    unique_ips = set(ip_addresses)
    count = len(unique_ips)
    elapsed_time = time.time() - start_time

    return count, elapsed_time


def hyperloglog_count(ip_addresses: List[str], precision: int = 14) -> tuple:
    """
    Наближений підрахунок унікальних IP-адрес за допомогою HyperLogLog.

    Args:
        ip_addresses: Список IP-адрес
        precision: Точність HyperLogLog

    Returns:
        Кортеж (оцінка кількості унікальних, час виконання)
    """
    start_time = time.time()
    hll = HyperLogLog(precision=precision)

    for ip in ip_addresses:
        hll.add(ip)

    count = hll.count()
    elapsed_time = time.time() - start_time

    return count, elapsed_time


def compare_methods(file_path: str) -> None:
    """
    Порівнює точний підрахунок та HyperLogLog.

    Args:
        file_path: Шлях до лог-файлу
    """
    print("Завантаження даних...")
    ip_addresses = load_log_data(file_path)

    if not ip_addresses:
        print("Немає даних для обробки!")
        return

    print(f"Завантажено {len(ip_addresses)} записів.\n")

    # Точний підрахунок
    print("Виконується точний підрахунок...")
    exact_unique, exact_time = exact_count(ip_addresses)

    # HyperLogLog підрахунок
    print("Виконується HyperLogLog підрахунок...")
    hll_unique, hll_time = hyperloglog_count(ip_addresses)

    # Виведення результатів у вигляді таблиці
    print("\nРезультати порівняння:")
    print(f"{'':>27} {'Точний підрахунок':>19} {'HyperLogLog':>13}")
    print(f"{'Унікальні елементи':>27} {exact_unique:>19.1f} {hll_unique:>13.1f}")
    print(f"{'Час виконання (сек.)':>27} {exact_time:>19.2f} {hll_time:>13.2f}")


if __name__ == "__main__":
    import os

    # Шлях до лог-файлу
    log_file = "lms-stage-access.log"

    # Якщо оригінальний файл не знайдено, використовуємо тестовий
    if not os.path.exists(log_file):
        print(f"Файл '{log_file}' не знайдено.")
        test_file = "test_log.txt"
        if os.path.exists(test_file):
            print(f"Використовується тестовий файл '{test_file}'.\n")
            log_file = test_file
        else:
            print("Запустіть generate_test_log.py для створення тестового файлу.")
            print("Або завантажте lms-stage-access.log з:")
            print(
                "https://drive.google.com/file/d/13NUCSG7l_z2B7gYuQubYIpIjJTnwOAOb/view"
            )
            exit(1)

    # Виконання порівняння
    compare_methods(log_file)
