# The "protected core" — encrypt this with tools/protect.py so it ships as
# core.enc. It is only decrypted in memory after a valid online authorization,
# then exec'd by the loader. Put the software's valuable logic here.

print(">>> [protected core] running — authorization verified, key delivered.")


def secret_algorithm(x: int) -> int:
    # stand-in for the logic you don't want shipped in the clear
    return (x * 2654435761) & 0xFFFFFFFF


print(">>> secret_algorithm(1337) =", secret_algorithm(1337))
