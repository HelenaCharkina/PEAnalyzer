using System;
using System.Collections.Generic;
using System.Text;

namespace PEAnalyzer.Structure
{
    public abstract class Headers
    {
    }

    public class DOS_Header : Headers
    {
        public string e_magic = "5a4d";
        public string e_lfanew;
        public bool ValidSignature (string sign)
        {
            return sign == e_magic;
        }

    }
    public class PE_Header : Headers
    {
        public string signature = "00004550";
        public bool ValidSignature (string sign)
        {
            return sign == signature;
        }
    }

    public class FileHeader : PE_Header
    {
        public string Machine; // Архитектура процессора
        public string NumberOfSections; // Кол-во секций
        public string TimeDateStamp; // Дата и время создания программы (число секунд с момента 16:00 31.12.1969)
        public string PointerToSymbolTable; // Указатель на таблицу символов
        public string NumberOfSymbols; // Число символов в таблице
        public string SizeOfOptionalHeader; // Размер дополнительного заголовка
        public string Characteristics; // Характеристика

        public string IsMachine (string value)
        {
            switch (value)
            {
                case "014c":
                    return "Означает, что программа может выполняться на x32";
                case "2000":
                    return "Означает, что программа может выполняться на процессорах Intel Itanium (Intel x64)";
                case "8664":
                    return "Означает, что программа может выполняться на процессорах AMD64 (x64)";
                default:
                    return "Не стандартное значение";
            }
        }
    }

    public class OptionHeader : PE_Header
    {
        public string Magic; // битность программы
        public string AddressOfEntryPoint; // адрес точки входа
        public string ImageBase; // предпочтительный адрес загрузки программы в память
        public string SectionAlignment; // относительный виртуальный адрес начала секций в виртуальной памяти
        public string FileAlignment; // смещение относительно начала файла начала секций в файле
        public string MajorSubsystemVersion; // необходимая версия windows 
        public string MinorSubsytemVersion; // необходимая версия windows 
        public string SizeOfImage; // размер загруженного файла в памяти
        public string SizeOfHeaders; // размер заголовков файла в памяти
        public string Subsystem; // тип подсистемы
        public string NumberOfRvaAndSizes; // число каталогов в массиве каталогов


        public string BitIs (string value)
        {
            switch (value)
            {
                case "010b":
                    return "Означает, что это x32 (x86) исполняемый образ";
                case "020b":
                    return "Означает, что это x64 исполняемый образ";
                case "0107":
                    return "Означает, что это ROM образ";
                default:
                    return "Не стандартное значение";
            }
        }

        public string SubsystemIs (string value)
        {
            switch (value)
            {
                case "0000":
                    return "Неизвестная подсистема.";
                case "0001":
                    return "Подсистема не требуется (драйверы устройств и собственные системные процессы).";
                case "0002":
                    return "Подсистема графического интерфейса пользователя (GUI) Windows.";
                case "0003":
                    return "Подсистема пользовательского интерфейса (CUI) Windows.";
                case "0005":
                    return "Подсистема CUI OS / 2.";
                case "0007":
                    return "Подсистема POSIX CUI.";
                case "0009":
                    return "Система Windows CE.";
                case "0010":
                    return "Приложение расширяемого интерфейса прошивки (EFI).";
                case "0011":
                    return "EFI драйвер с сервисами загрузки.";
                case "0012":
                    return "EFI драйвер с сервисами во время выполнения.";
                case "0013":
                    return "Образ EFI ROM.";
                case "0014":
                    return "Система Xbox.";
                case "0016":
                    return "Загрузочное приложение.";
                default:
                    return "Не стандартное значение";
            }
        }
    }

    public class SectionHeader : Headers
    {
        public string Name; // имя секции в ASCII кодировке
        public string VirtualSize; // размер секции в виртуальной памяти
        public string VirtualAddress; // относительный адрес секции в виртуальной памяти
        public string SizeOfRawData; // размер секции в файле          
        public string PointerToRawData; //  указатель на эти данные
        public string PointerToRelocations; // указатель файла на начало записи перемещения для раздела
        public string PointerToLinenumbers; // указатель файла на начало записи номера строки для раздела.
        public string NumberOfRelocations; // количество записей перемещения для раздела.
        public string NumberOfLinenumbers; // количество строк-номеров записей для раздела. 
        public string Characteristics; // атрибуты секции

        public string GetCharacteristics(string character)
        {
            string ans = "";
            if (character.Substring(6, 2) == "20") ans += "Раздел содержит исполняемый код. ";
            else if (character.Substring(6, 2) == "40") ans += "Раздел содержит инициализированные данные. ";
            else if (character.Substring(6, 2) == "80") ans += "Раздел содержит неинициализированные данные. ";

            if (character.Substring(4, 2) == "10") ans += "Раздел содержит данные COMDAT. ";
            else if (character.Substring(4, 2) == "80") ans += "Раздел содержит данные, на которые ссылается глобальный указатель (GP). ";

            if (character.Substring(0, 2) == "01") ans += "Раздел содержит расширенные перемещения. ";
            else if (character.Substring(0, 2) == "02") ans += "Раздел может быть отброшен по мере необходимости. ";
            else if (character.Substring(0, 2) == "04") ans += "Раздел не может быть кэширован. ";
            else if (character.Substring(0, 2) == "08") ans += "Раздел не доступен для просмотра. ";
            else if (character.Substring(0, 2) == "10") ans += "Раздел может быть разделен в памяти. ";
            else if (character.Substring(0, 2) == "20") ans += "Раздел может быть выполнен как код. ";
            else if (character.Substring(0, 2) == "40") ans += "Раздел можно прочитать. ";
            else if (character.Substring(0, 2) == "80") ans += "В раздел можно написать. ";




            return ans;
        }
    }
}
