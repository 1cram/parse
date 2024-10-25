#!/bin/bash

P7S_FILE=$1

# Trova l'offset degli attributi autenticati dinamicamente
ATTR_OFFSET=$(openssl asn1parse -inform DER -in "$P7S_FILE" | grep -B1 "SET" | grep "cont \[ 0 \]" | cut -d: -f1)

# Estrai gli attributi autenticati
openssl asn1parse -inform DER -in "$P7S_FILE" -strparse $ATTR_OFFSET -out auth_attrs.der

# Estrai e ordina gli OID in base ai loro bytes DER
for offset in $(openssl asn1parse -inform DER -in auth_attrs.der | grep ':OBJECT' | cut -d: -f1); do
    openssl asn1parse -inform DER -in auth_attrs.der -strparse $offset -out "oid_$offset.der"
    # Concatena offset e bytes DER dell'OID per l'ordinamento
    echo "$offset $(xxd -p "oid_$offset.der")" >> oids_bytes.txt
done

# Ordina in base ai bytes DER
sort -k2 oids_bytes.txt > sorted_oids.txt

# Estrai e concatena gli attributi nell'ordine corretto
> reordered_attrs.der
while read offset rest; do
    openssl asn1parse -inform DER -in auth_attrs.der -strparse $offset -noout -out temp.der
    cat temp.der >> reordered_attrs.der
done < sorted_oids.txt

# Codifica DER della lunghezza
length=$(wc -c < reordered_attrs.der)
if [ $length -lt 128 ]; then
    printf "31%02x" $length > header.der
else
    # Gestione corretta delle lunghezze DER lunghe
    len_bytes=$(printf "%x" $length | sed 's/.\{2\}/& /g')
    num_bytes=$(echo $len_bytes | wc -w)
    printf "31%02x%s" $((128 + num_bytes)) $len_bytes > header.der
fi

# Crea il SET OF finale
cat header.der reordered_attrs.der > final_auth_attrs.der

# Calcola l'hash SHA-256
openssl dgst -sha256 -c final_auth_attrs.der

# Pulizia
rm *.der oids_bytes.txt sorted_oids.txt