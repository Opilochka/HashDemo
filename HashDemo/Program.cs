using System.Text;

namespace HashDemo
{
    /// <summary>
    /// Содержит реализации хэш-функций: ручную реализацию SHA-256 и упрощённую демонстрационную функцию.
    /// </summary>
    public static class HashFunctions
    {
        // Константы раундов (первые 32 бита дробных частей квадратных корней первых 64 простых чисел)
        private static readonly uint[] K =
        [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];

        // Начальные значения хэша (первые 32 бита дробных частей квадратных корней первых 8 простых чисел)
        private static readonly uint[] H0 =
        [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ];

        /// <summary>
        /// Вычисляет хэш SHA-256 для заданной строки.
        /// </summary>
        /// <param name="input">Входная строка в кодировке UTF-8.</param>
        /// <returns>Хэш в виде шестнадцатеричной строки (64 символа, строчные буквы).</returns>
        /// <exception cref="ArgumentNullException">Если входная строка равна null.</exception>
        public static string ComputeSha256Hash(string input)
        {
            ArgumentNullException.ThrowIfNull(input);

            byte[] message = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = ComputeSha256(message);

            // Преобразуем в hex
            StringBuilder sb = new();
            foreach (byte b in hashBytes)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        // Внутренняя реализация SHA-256 над массивом байтов
        private static byte[] ComputeSha256(byte[] message)
        {
            // 1. Добавление бита '1'
            long originalLength = message.Length * 8; // длина в битах
            int paddingLength = (int)((56 - (message.Length % 64)) % 64);
            if (paddingLength == 0) paddingLength = 64;

            byte[] padded = new byte[message.Length + paddingLength + 8];
            Array.Copy(message, padded, message.Length);
            padded[message.Length] = 0x80; // 10000000

            // 2. Добавление 64-битной длины в big-endian в конец
            for (int i = 0; i < 8; i++)
            {
                padded[padded.Length - 8 + i] = (byte)((originalLength >> (56 - i * 8)) & 0xFF);
            }

            // 3. Инициализация рабочих переменных
            uint a, b, c, d, e, f, g, h;
            uint[] w = new uint[64];

            // Копия начальных значений
            uint[] hVals = new uint[8];
            Array.Copy(H0, hVals, 8);

            // 4. Обработка блоков по 512 бит (64 байта)
            for (int chunkStart = 0; chunkStart < padded.Length; chunkStart += 64)
            {
                // Подготовка расширенного сообщения W[0..63]
                for (int i = 0; i < 16; i++)
                {
                    w[i] = (uint)((padded[chunkStart + i * 4] << 24) |
                                  (padded[chunkStart + i * 4 + 1] << 16) |
                                  (padded[chunkStart + i * 4 + 2] << 8) |
                                  (padded[chunkStart + i * 4 + 3]));
                }

                for (int i = 16; i < 64; i++)
                {
                    uint s0 = RightRotate(w[i - 15], 7) ^ RightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
                    uint s1 = RightRotate(w[i - 2], 17) ^ RightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }

                // Инициализация восьми рабочих переменных
                a = hVals[0]; b = hVals[1]; c = hVals[2]; d = hVals[3];
                e = hVals[4]; f = hVals[5]; g = hVals[6]; h = hVals[7];

                // Основной цикл раундов
                for (int i = 0; i < 64; i++)
                {
                    uint s1 = RightRotate(e, 6) ^ RightRotate(e, 11) ^ RightRotate(e, 25);
                    uint ch = (e & f) ^ ((~e) & g);
                    uint temp1 = h + s1 + ch + K[i] + w[i];
                    uint s0 = RightRotate(a, 2) ^ RightRotate(a, 13) ^ RightRotate(a, 22);
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    uint temp2 = s0 + maj;

                    h = g;
                    g = f;
                    f = e;
                    e = d + temp1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp1 + temp2;
                }

                // Добавление к текущему хэшу
                hVals[0] += a;
                hVals[1] += b;
                hVals[2] += c;
                hVals[3] += d;
                hVals[4] += e;
                hVals[5] += f;
                hVals[6] += g;
                hVals[7] += h;
            }

            // Формируем результат
            byte[] hash = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                hash[i * 4] = (byte)(hVals[i] >> 24);
                hash[i * 4 + 1] = (byte)(hVals[i] >> 16);
                hash[i * 4 + 2] = (byte)(hVals[i] >> 8);
                hash[i * 4 + 3] = (byte)(hVals[i]);
            }

            return hash;
        }

        // Вспомогательная функция: циклический сдвиг вправо на n битов
        private static uint RightRotate(uint x, int n)
        {
            return (x >> n) | (x << (32 - n));
        }

        /// <summary>
        /// Упрощённая хэш-функция, возвращающая сумму ASCII-кодов символов по модулю 100.
        /// </summary>
        /// <param name="input">Входная строка для хэширования.</param>
        /// <returns>Целое число от 0 до 99 — результат упрощённого хэширования.</returns>
        /// <remarks>
        /// Пример коллизии: "ab" и "ba" → оба дают 195 % 100 = 95.
        /// </remarks>
        public static int SimpleHash(string input)
        {
            ArgumentNullException.ThrowIfNull(input);

            int sum = 0;
            foreach (char c in input)
            {
                sum += (int)c;
            }
            return sum % 100;
        }
    }

    /// <summary>
    /// Демонстрационный класс для запуска примеров хэширования и поиска коллизий.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Точка входа программы. Запускает интерактивный режим:
        /// позволяет вводить строки и получать их SHA-256 и упрощённый хэш.
        /// Также поддерживает проверку коллизии для двух строк.
        /// </summary>
        /// <param name="args">Аргументы командной строки (не используются).</param>
        public static void Main(string[] args)
        {
            ArgumentNullException.ThrowIfNull(args);
            Console.WriteLine("=== Хэш-демонстратор: SHA-256 (реализация с нуля) + упрощённая функция ===\n");

            // Проверка на известном тестовом векторе
            string testInput = "abc";
            string computed = HashFunctions.ComputeSha256Hash(testInput);
            string expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            Console.WriteLine($"Тест SHA-256 на входе \"{testInput}\": {(computed == expected ? "ПРОЙДЕН" : "ОШИБКА")}\n");

            while (true)
            {
                Console.WriteLine("Выберите действие:");
                Console.WriteLine("1. Посчитать хэши для одной строки");
                Console.WriteLine("2. Проверить коллизию для двух строк (упрощённая функция)");
                Console.WriteLine("3. Выйти");
                Console.Write("Ваш выбор (1/2/3): ");

                string? choice = Console.ReadLine()?.Trim();

                switch (choice)
                {
                    case "1":
                        Console.Write("\nВведите строку для хэширования: ");
                        string? input1 = Console.ReadLine();
                        if (input1 == null) break;

                        try
                        {
                            string sha256 = HashFunctions.ComputeSha256Hash(input1);
                            int simple = HashFunctions.SimpleHash(input1);

                            Console.WriteLine($"\n--- Результаты ---");
                            Console.WriteLine($"SHA-256: {sha256}");
                            Console.WriteLine($"SimpleHash (mod 100): {simple}\n");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Ошибка: {ex.Message}\n");
                        }
                        break;

                    case "2":
                        Console.Write("\nВведите первую строку: ");
                        string? strA = Console.ReadLine();
                        Console.Write("Введите вторую строку: ");
                        string? strB = Console.ReadLine();

                        if (strA == null || strB == null) break;

                        try
                        {
                            int hashA = HashFunctions.SimpleHash(strA);
                            int hashB = HashFunctions.SimpleHash(strB);

                            Console.WriteLine($"\n--- Сравнение ---");
                            Console.WriteLine($"SimpleHash(\"{strA}\") = {hashA}");
                            Console.WriteLine($"SimpleHash(\"{strB}\") = {hashB}");
                            Console.WriteLine($"Коллизия: {(hashA == hashB ? "ДА" : "НЕТ")}\n");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Ошибка: {ex.Message}\n");
                        }
                        break;

                    case "3":
                        Console.WriteLine("\nВыход. До свидания!");
                        return;

                    default:
                        Console.WriteLine("\nНекорректный выбор. Попробуйте снова.\n");
                        break;
                }
            }
        }
    }
}