import EncryptedMessenger

def test_secret():
    testSecret, testSend = EncryptedMessenger.secretMaker()
    print(testSecret)
    assert(testSecret)
    #assert(False)

def test_encryption():
    assert(False)

def test_hmac():
    assert(False)

def test_pad():
    assert(False)
    