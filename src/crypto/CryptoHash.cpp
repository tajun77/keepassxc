/*
 *  Copyright (C) 2010 Felix Geyer <debfx@fobos.de>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "CryptoHash.h"

#include <botan/hash.h>
#include <botan/mac.h>

#include "crypto/Crypto.h"

class CryptoHashPrivate
{
public:
    std::unique_ptr<Botan::HashFunction> hashFunction;
    std::unique_ptr<Botan::MessageAuthenticationCode> hmacFunction;
};

CryptoHash::CryptoHash(Algorithm algo, bool hmac)
    : d_ptr(new CryptoHashPrivate())
{
    Q_D(CryptoHash);

    Q_ASSERT(Crypto::initialized());

    switch (algo) {
    case CryptoHash::Sha256:
        if (hmac) {
            d_ptr->hmacFunction.reset(Botan::MessageAuthenticationCode::create("HMAC(SHA-256)").release());
        } else {
            d_ptr->hashFunction.reset(Botan::HashFunction::create("SHA-256").release());
        }
        break;
    case CryptoHash::Sha512:
        if (hmac) {
            d_ptr->hmacFunction.reset(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)").release());
        } else {
            d_ptr->hashFunction.reset(Botan::HashFunction::create("SHA-512").release());
        }
        break;
    default:
        Q_ASSERT(false);
        break;
    }
}

CryptoHash::~CryptoHash()
{
    Q_D(CryptoHash);
    delete d_ptr;
}

void CryptoHash::addData(const QByteArray& data)
{
    Q_D(CryptoHash);

    if (data.isEmpty()) {
        return;
    }

    try {
        if (d->hmacFunction) {
            d->hmacFunction->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        } else if (d->hashFunction) {
            d->hashFunction->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        }
    } catch (std::exception& e) {
        qWarning("CryptoHash::update failed to add data: %s", e.what());
    }
}

void CryptoHash::setKey(const QByteArray& data)
{
    Q_D(CryptoHash);

    if (d->hmacFunction) {
        try {
            d->hmacFunction->set_key(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        } catch (std::exception& e) {
            qWarning("CryptoHash::setKey failed to set HMAC key: %s", e.what());
        }
    }
}

QByteArray CryptoHash::result() const
{
    Q_D(const CryptoHash);

    Botan::secure_vector<uint8_t> result;
    if (d->hmacFunction) {
        result = d->hmacFunction->final();
    } else if (d->hashFunction) {
        result = d->hashFunction->final();
    }
    return QByteArray(reinterpret_cast<const char*>(result.data()), result.size());
}

QByteArray CryptoHash::hash(const QByteArray& data, Algorithm algo)
{
    CryptoHash cryptoHash(algo);
    cryptoHash.addData(data);
    return cryptoHash.result();
}

QByteArray CryptoHash::hmac(const QByteArray& data, const QByteArray& key, Algorithm algo)
{
    CryptoHash cryptoHash(algo, true);
    cryptoHash.setKey(key);
    cryptoHash.addData(data);
    return cryptoHash.result();
}
