using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using TextCopy;
using Yubico.Core.Buffers;
using Yubico.YubiKey;
using Yubico.YubiKey.Cryptography;
using Yubico.YubiKey.Piv;

const string data = "lGuYZXjEz9DqbCr/yFJqutHqsa/8aC7PFig4M9yvaV+YUYSDz7nJgbon7+A4hA2neeaj6irH6ZTRn6CSN5/q3ZUIabKg7RVPZvil2HJSSsiUB8YI4kxoq3WJ2kz6vAVwDmov2Axu3ZrtMYx5oqqhL8HjOZUq6pgZOk0lQq4OWAzGeUpUfBGC8SDy819s12c+Upu++DCp5AU24Qags5J7l75KXn71+f2XcgpOYUI4qdXi57BQBcOYD0VsJ+00BQW7RBgup3EmPfSITrwgAC0huTNvRnYpCCIhoyiHJ8Jqy2oFtdGUAq1XIChi1lUPozzQlLxwH2oLu7FhDXtlZic35g==";

START:
var yubiKeys = YubiKeyDevice.FindAll();
var connectedKeyCount = yubiKeys.Count();

IYubiKeyDevice? targetYubiKey = null;

if (connectedKeyCount == 0)
{
    Console.WriteLine("Please insert the YubiKey first.");
    Console.WriteLine("Press any key to retry.");
    Console.Read();
    goto START;
}
else if (connectedKeyCount == 1)
{
    targetYubiKey = yubiKeys.First();
}
else
{
    targetYubiKey = SelectDevice(yubiKeys, connectedKeyCount);
}
Console.Clear();
Console.WriteLine($"Using {targetYubiKey.SerialNumber}");
Console.WriteLine("Connecting to the YubiKey...");

using (var piv = new PivSession(targetYubiKey))
{
    piv.KeyCollector = KeyCollectorPrompt;

RETRY:
    try
    {
        byte[] rawDecryptedData = piv.Decrypt(PivSlot.Authentication, Convert.FromBase64String(data));

        if (!RsaFormat.TryParsePkcs1Oaep(rawDecryptedData, RsaFormat.Sha256, out var decryptedData))
            Console.WriteLine("\n\nPares Pcks10aep failed!");

        var decryptedString = Encoding.UTF8.GetString(decryptedData);

        ClipboardService.SetText(decryptedString);
        Console.WriteLine("\n\n\n" + decryptedString);
    }
    catch (Exception ex)
    {
        Console.WriteLine();
        Console.WriteLine(ex.Message);
        Console.WriteLine();
        goto RETRY;
    }
}

Console.WriteLine("\n\nPress ENTER to exit.");
Console.ReadLine();
ClipboardService.SetText("");

IYubiKeyDevice SelectDevice(IEnumerable<IYubiKeyDevice> yubiKeys, int count)
{
RESELECT:
    Console.WriteLine("You have these keys inserted:");
    foreach (var (yubiKey, index) in yubiKeys.Select((yubiKey, index) => (yubiKey, index)))
        Console.WriteLine($"[{index}] {yubiKey.SerialNumber}");
    Console.Write($"\nPlease select the YubiKey you want to use (0~{count - 1}):");

    if (!Int32.TryParse(Console.ReadLine(), out var selected))
    {
        Console.Clear();
        Console.WriteLine("The input should be a number!\n");
        goto RESELECT;
    }

    if (selected < 0 || selected >= count)
    {
        Console.Clear();
        Console.WriteLine($"The input should be from 0 to {count - 1}!\n");
        goto RESELECT;
    }

    return yubiKeys.ElementAt(selected);
}

static bool KeyCollectorPrompt(KeyEntryData entryData)
{
    switch (entryData.Request)
    {
        case KeyEntryRequest.Release:
            return true;
        case KeyEntryRequest.VerifyPivPin:
            Console.Write("Enter the PIN:");
            entryData.SubmitValue(Encoding.ASCII.GetBytes(ReadPassword()));
            return true;
        case KeyEntryRequest.AuthenticatePivManagementKey:
            Console.Write("Enter the PIV management key:");
            entryData.SubmitValue(Hex.HexToBytes(Console.ReadLine() ?? "").ToArray());
            return true;
        default:
            Console.WriteLine($"Unknown Request {entryData.Request}.");
            return false;
    }
}

static string ReadPassword()
{
    string password = "";
    ConsoleKeyInfo key;
    while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
    {
        if (key.Key == ConsoleKey.Backspace)
        {
            if (password.Length == 0)
                continue;

            password = password.Substring(0, password.Length - 1);
            Console.Write("\b \b");
        }
        else
        {
            password += key.KeyChar;
            Console.Write("*");
        }
    } 

    return password.Trim();
}

static string Encrypt(PivSession piv, string text)
{
    PivMetadata pivMetadata = piv.GetMetadata(PivSlot.Authentication);

    var rsaPublic = (PivRsaPublicKey)pivMetadata.PublicKey;

    var rsaParams = new RSAParameters
    {
        Modulus = rsaPublic.Modulus.ToArray(),
        Exponent = rsaPublic.PublicExponent.ToArray()
    };

    RSA rsa = RSA.Create(rsaParams);
    var encryptedDataBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.OaepSHA256);
    rsa.Dispose();
    return Convert.ToBase64String(encryptedDataBytes);
}