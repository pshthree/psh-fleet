import "hash"

rule EICAR_Test_File
{
    meta:
        name = "Test.EICAR"
        description = "EICAR antivirus test file. Harmless. Proves the scan path works end to end."
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    condition:
        // Matched by hash so the test string never sits in this repository,
        // where other scanners would flag it. The spec allows trailing
        // whitespace up to 128 bytes in total.
        filesize >= 68 and filesize <= 128 and
        hash.sha256(0, 68) == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
}
