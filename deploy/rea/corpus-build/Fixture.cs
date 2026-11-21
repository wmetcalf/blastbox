namespace Loadout.Fixture;

// Benign Loadout REA corpus fixture (.NET class library).
public static class Greeter
{
    public const string Endpoint = "https://loadout-dotnet-fixture.example.net/api/v1";
    public const string Mutex = "Global\\LoadoutFixtureMutex";
    public static string Hello(int n) => $"hello loadout dotnet {n * 3 + 7}";
}
