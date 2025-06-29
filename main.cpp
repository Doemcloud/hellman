#include <iostream>
#include <cmath>
#include <stdexcept>
#include <string>
#include <limits>

using namespace std;

const long long MAX_VALUE = 1000000; // Максимальное допустимое значение для чисел

bool isPrime(long long n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (long long i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

bool isValidGenerator(long long g, long long p) {
    return g > 1 && g < p;
}

class Main {
private:
    long long generator;
    long long prime;
    long long privateKey;
    long long publicKey;

    long long powerMod(long long base, long long exp, long long mod) const {
        if (base <= 0 || mod <= 1) return 0;
        long long result = 1;
        base %= mod; // Приведение базы к модулю
        while (exp > 0) {
            if (exp & 1) result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

public:
    Main(long long g, long long p, long long privKey)
        : generator(g), prime(p), privateKey(privKey) {
        if (!isPrime(p) || !isValidGenerator(g, p) || privKey <= 0 || privKey >= p) {
            throw invalid_argument("Некорректные параметры: p должен быть простым, 1 < g < p, 0 < privKey < p");
        }
        publicKey = powerMod(g, privateKey, p);
    }

    long long getPublicKey() const { return publicKey; }

    long long computeSharedSecret(long long otherPublicKey) const {
        if (otherPublicKey <= 0 || otherPublicKey >= prime) {
            throw invalid_argument("Открытый ключ должен быть в диапазоне 0 < key < p");
        }
        return powerMod(otherPublicKey, privateKey, prime);
    }
};

class Participant {
private:
    Main dh;
    long long sharedKey;

public:
    Participant(long long g, long long p, long long privateKey)
        : dh(g, p, privateKey), sharedKey(0) {}

    long long getPublicKey() const { return dh.getPublicKey(); }

    long long computeSharedSecret(long long otherPublicKey) const {
        return dh.computeSharedSecret(otherPublicKey);
    }

    void setSharedKey(long long key) {
        if (key <= 0) throw runtime_error("Общий ключ должен быть положительным");
        sharedKey = key;
    }

    string encrypt(const string& plaintext) const {
        if (sharedKey == 0 || plaintext.empty()) {
            throw runtime_error("Общий ключ не установлен или текст пуст");
        }
        string ciphertext;
        for (char c : plaintext) {
            ciphertext += c ^ static_cast<char>(sharedKey);
        }
        return ciphertext;
    }

    string decrypt(const string& ciphertext) const {
        if (sharedKey == 0 || ciphertext.empty()) {
            throw runtime_error("Общий ключ не установлен или текст пуст");
        }
        string plaintext;
        for (char c : ciphertext) {
            plaintext += c ^ static_cast<char>(sharedKey);
        }
        return plaintext;
    }
};

long long inputNumber(const string& prompt) {
    long long value;
    cout << prompt;
    if (!(cin >> value) || value <= 0 || value > MAX_VALUE) {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        throw invalid_argument("Значение должно быть положительным и не превышать " + to_string(MAX_VALUE));
    }
    return value;
}

int main() {
    try {
        long long g = inputNumber("Введите генератор (g): ");
        long long p = inputNumber("Введите модуль (p, простое число): ");
        long long a = inputNumber("Введите секретный ключ первого участника (a): ");
        long long b = inputNumber("Введите секретный ключ второго участника (b): ");

        cout << "Введите текст для шифрования: ";
        string message;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        getline(cin, message);
        if (message.empty()) throw invalid_argument("Текст не может быть пустым");

        Participant participant1(g, p, a);
        Participant participant2(g, p, b);

        long long sharedKey1 = participant1.computeSharedSecret(participant2.getPublicKey());
        long long sharedKey2 = participant2.computeSharedSecret(participant1.getPublicKey());

        if (sharedKey1 != sharedKey2) throw runtime_error("Общие ключи не совпадают");

        participant1.setSharedKey(sharedKey1);
        participant2.setSharedKey(sharedKey2);

        cout << "Общий секретный ключ: " << sharedKey1 << "\n";
        string ciphertext = participant1.encrypt(message);
        cout << "Зашифрованный текст: " << ciphertext << "\n";
        string decryptedMessage = participant2.decrypt(ciphertext);
        cout << "Расшифрованный текст: " << decryptedMessage << "\n";

        cout << (decryptedMessage == message ? "Текст успешно расшифрован!\n" : "Ошибка: текст не совпадает.\n");
    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << "\n";
    }
    return 0;
}
