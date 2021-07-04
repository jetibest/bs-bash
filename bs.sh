#!/bin/bash

# Initialize variables
__bs_home="${BS_HOME:-~/.bs}"
__bs_default_port="2770"
__bs_default_secure_port="2771"

parse_address()
{
	__fn_addr="$1"
	
	# parse user:
	__fn_addr_user="${__fn_addr%%@*}"
	if [ "${__fn_addr:0:1}" = "@" ]
	then
		__fn_addr_user="$__fn_addr"
		__fn_addr_user="${__fn_addr_user%%:*}"
		__fn_addr_user="${__fn_addr_user%%#*}"
		__fn_addr_user="${__fn_addr_user%%/*}"
		__fn_addr_user="${__fn_addr_user%%&*}"
	fi
	
	# parse host:
	__fn_addr_host="${__fn_addr:${#__fn_addr_user}}"
	__fn_addr_host="${__fn_addr_host%%:*}"
	__fn_addr_host="${__fn_addr_host%%#*}"
	__fn_addr_host="${__fn_addr_host%%/*}"
	__fn_addr_host="${__fn_addr_host%%&*}"
	__fn_addr_host="${__fn_addr_host##@}"
	
	# parse port:
	__fn_addr_port="${__fn_addr#*:}"
	__fn_addr_port="${__fn_addr_port%%:*}"
	__fn_addr_port="${__fn_addr_port%%#*}"
	__fn_addr_port="${__fn_addr_port%%/*}"
	__fn_addr_port="${__fn_addr_port%%&*}"
	if [ "$__fn_addr_port" != "${__fn_addr_port/[^0-9]/}" ]
	then
		__fn_addr_port="$__bs_default_secure_port"
	fi
	
	# parse path:
	__fn_addr_other="${__fn_addr%%:*}"
	__fn_addr_other="${__fn_addr_other%%#*}"
	__fn_addr_other="${__fn_addr_other%%/*}"
	__fn_addr_other="${__fn_addr_other%%&*}"
	__fn_addr_path_offset="${#__fn_addr_other}"
	__fn_addr_path="${__fn_addr:$__fn_addr_path_offset}"
	
	case "$__fn_addr_path" in
        ":$__fn_addr_port:"*)
            __fn_addr_path_offset=$((__fn_addr_path_offset + ${#__fn_addr_port} + 1))
            __fn_addr_path="${__fn_addr:$__fn_addr_path_offset}"
        ;;
        ":$__fn_addr_port#"*)
            __fn_addr_path_offset=$((__fn_addr_path_offset + ${#__fn_addr_port} + 1))
            __fn_addr_path="${__fn_addr:$__fn_addr_path_offset}"
        ;;
        ":$__fn_addr_port/"*)
            __fn_addr_path_offset=$((__fn_addr_path_offset + ${#__fn_addr_port} + 1))
            __fn_addr_path="${__fn_addr:$__fn_addr_path_offset}"
        ;;
        ":$__fn_addr_port&"*)
            __fn_addr_path_offset=$((__fn_addr_path_offset + ${#__fn_addr_port} + 1))
            __fn_addr_path="${__fn_addr:$__fn_addr_path_offset}"
        ;;
	esac
	
	if [ "${__fn_addr_path:0:1}" = ":" ]
	then
        __fn_addr_path="${__fn_addr_path:1}"
	fi
	
	__fn_addr=("$__fn_addr_user" "$__fn_addr_host" "$__fn_addr_port" "$__fn_addr_path")
	
	echo "${__fn_addr[*]}"
}


# Exit on any error:
set -e


# Ensure home-directory exists:
if ! [ -e "$__bs_home" ]
then
	mkdir -p "$__bs_home"
	chmod 700 "$__bs_home"
fi


# If no username exists, use local username:
if [ -e "$__bs_home/user" ]
then
	read __bs_user <"$__bs_home/user"
fi
if [ -z "$__bs_user" ]
then
	__bs_user="$(whoami)"
	echo "$__bs_user" > "$__bs_home/user"
fi


# If no hostname exists, use local hostname:
if [ -e "$__bs_home/host" ]
then
	read __bs_host <"$__bs_home/host"
fi
if [ -z "$__bs_host" ]
then
	__bs_host="$(hostname)"
	echo "$__bs_host" > "$__bs_home/host"
fi


# If no keypair exists, generate a new keypair (as x509 cert):
if ! [ -e "$__bs_home/key.pem" ]
then
	# generate keypair in pem format (x509 certificate and private key)
	openssl req -x509 -nodes -newkey rsa:4096 -subj "/CN=localhost" -keyout "$__bs_home/key.pem" -out "$__bs_home/cert.pem" -days 36500
	
	# export to p12 format for whatever future use we would want to have that
	openssl pkcs12 -export -in "$__bs_home/cert.pem" -inkey "$__bs_home/key.pem" -out "$__bs_home/key.p12"
	
	# ensure no leaking of private keys
	chmod 600 "$__bs_home/key.pem" "$__bs_home/key.p12"
    
fi


# Handle command:

if [ "$1" = "add" ] # bs-gpg add <user@host> [host][:port]
then
	# Add a contact by their public key (in stdin) and address
	
	addr=($(parse_address "$2"))
	
	# Check usage
	if [ -z "$addr" ] || [ -z "${addr[0]}" ] || [ -z "${addr[1]}" ]
	then
		echo "error: Invalid usage. Use: bs-gpg add <user@host>" >&2
		exit 1
	fi
	
	# Setup contact directory
	contact_dir="$__bs_home/contacts/${addr[0]}@${addr[1]}"
	if ! [ -e "$contact_dir" ]
	then
		mkdir -p "$contact_dir"
	fi
	
	# Write public-key to contact file
	cat "${3:---}" > "$contact_dir/cert.pem"
	
	# Write custom port to contact file
	if [ "${addr[2]}" -ne "$__bs_default_secure_port" ]
	then
		echo "${addr[2]}" > "$contact_dir/port"
	fi
	
	# Import public-key in gpg
	# $gpg --import "$__bs_home/contacts/$addr"

elif [ "$1" = "push" ] # bs-gpg push <user@host> [host][:port]
then
	# Connect to the target host or override host with another service
	
	target_addr=($(parse_address "$2"))
	connect_addr=($(parse_address "$3"))
	
	conn_host="${target_addr[1]}"
	conn_port="${target_addr[2]}"
	if [ -n "${connect_addr[1]}" ]
	then
		conn_host="${connect_addr[1]}"
	fi
	if [ -n "${connect_addr[2]}" ] && [ "${connect_addr[2]}" -ne "$__bs_default_secure_port" ]
	then
		conn_port="${connect_addr[2]}"
	fi
	
    contact="${target_addr[0]}@${target_addr[1]}"
    
    if ! [ -e "$__bs_home/contacts/$contact" ]
    then
        echo "error: Contact not found ($__bs_home/contacts/$contact)." >&2
        exit 1
        
	elif ! [ -e "$__bs_home/contacts/$contact/cert.pem" ]
	then
        echo "error: No public key found for contact: $contact ($__bs_home/contacts/$contact/cert.pem)." >&2
        
        if [ -e "$__bs_home/contacts/$contact/port" ]
        then
            contact_port=":$(cat "$__bs_home/contacts/$contact/port")"
        else
            contact_port=""
        fi
        echo "hint: Try to add the contact using: $0 pull \"$contact$contact_port&cert.pem\" $3 | $0 add $contact" >&2
        exit 1
	fi
	
	# Generate a symmetric encryption key
	key_file="$__bs_home/.tmp-random.$(date +'%s%N').bin"
	openssl rand -base64 32 >"$key_file"
	
	# Encrypt the symmetric encryption key
	openssl rsautl -encrypt -certin -inkey "$__bs_home/contacts/$contact/cert.pem" -in "$key_file" -out "$key_file.enc"
	
	# Build the header
	header_file="$__bs_home/.tmp-header.$(date +'%s%N').txt"
	cat <<EOF >"$header_file"
bsp push $2
from: $__bs_user@$__bs_host
date: $(date --iso-8601)
encryption-method: openssl aes-256-cbc
encryption-key: $(cat "$key_file.enc" | base64 -w 0)
EOF
    
    # Create signature of header
    header_hash_file="$header_file.sha256"
    openssl dgst -sha256 "$header_file" >"$header_hash_file"
	
	# Securely connect with the conn_host:conn_port
	{
        # Send header signature:
        echo -n "bsp signature "
        openssl rsautl -sign -inkey "$__bs_home/key.pem" -keyform pem -in "$header_hash_file" | base64 -w 0
        echo "hash: sha256"
        echo ""
        
        # Send blank line before next header
        echo ""
        
        # Send header:
        cat "$header_file"
        
        # Send blank line before data payload:
        echo ""
        
        # Send encrypted payload stream:
        # use stdbuf --output=L to pass through data per line instead of per 4096 bytes, this is for the input of openssl
        # bufsize lower than 16 has no effect, this is for the output of openssl
        # the limitation is that we cannot send less than 16 bytes at a time, which should not be an issue
        stdbuf --output=L openssl aes-256-cbc -pbkdf2 -bufsize 16 -kfile "$key_file"
        
    } | openssl s_client -cert "$__bs_home/cert.pem" -key "$__bs_home/key.pem" -connect "$conn_host:$conn_port"
	
	rm -f "$bsp_packet_file" "$key_file" "$header_file" "$header_hash_file"

elif [ "$1" = "listen" ]
then
    
    bind_addr=($(parse_address "$2"))
    
    # listen, receive push/pull requests
    # store push in local filesystem
    
    echo "Listening at 127.0.0.1:2770 for connections..."
    
    bind_host="${bind_addr[1]}"
    
    bind_port="${bind_addr[2]}"
    if [ "$bind_port" = "$__bs_default_secure_port" ]
    then
        bind_port="$__bs_default_port"
    fi
    
    ncat -k -l -c "$0 accept" "${bind_host:-127.0.0.1}" "${bind_port:-$__bs_default_port}"
    
    
elif [ "$1" == "accept" ]
then
    
    # this is a separate command, because we may also do a non-socket transfer directly
    # stdin is from the socket input
    # stdout goes to the socket output
    
    # note: we must support \r\n as well, hence \r must be trimmed off when using the value, but not taking off for the hash calculation for the signature
    # note: any binary values in the header value must be base64 encoded as a standard
    
    # careful, value proto cmd and value must have precisely 1 whitespace between them, and no trailing whitespaces must exist either (except for \r, which is fine)
    
    cleanup_array=()
    cleanup()
    {
        for cmd in "${cleanup_array[@]}"
        do
            $cmd
        done
    }
    trap 'cleanup' EXIT
    
    while IFS=' ' read -r proto cmd _value
    do
        value="${_value%$'\r'}"
        
        if [ "$proto" = "bsp" ]
        then
            # careful, value may not have additional spaces at the beginning or end, or the signature will fail, due to trimming by read
            header_file="$__bs_home/.tmp-header.$(date +'%s%N').txt"
            
            echo "$proto $cmd $_value" >"$header_file"
            while IFS= read -r line
            do
                if [ -z "$line" ]
                then
                    break
                fi
                
                # read raw lines first, otherwise spaces may have been trimmed off, and we would be unable to reliably generate the same hash for the signature
                echo "$line" >>"$header_file"
            done
            
            cleanup_array+=(rm -f "\"$header_file\"")
            
            if [ "$cmd" = "signature" ]
            then
                signature_header_file="$header_file"
                signature="$value"
                hash_fn="sha256"
                
                while IFS=$'\r :' read -r key value
                do
                    if [ -z "$key" ]
                    then
                        break
                    fi
                    
                    if [ "$key" = "hash" ]
                    then
                        hash_fn="$value"
                        
                    elif [ "$key" = "value" ] || [ "$key" = "signature" ]
                    then
                        signature="$value"
                    
                    fi
                done <"$header_file"
            
            elif [ "$cmd" = "push" ]
            then
                
                # parse header:
                
                bsp_packet_recipient=""
                bsp_packet_from=""
                bsp_packet_date=""
                bsp_packet_encryption_method=""
                bsp_packet_encryption_key=""
                
                while IFS=$'\r :' read -r key value
                do
                    if [ -z "$key" ]
                    then
                        break
                    fi
                    
                    if [ "$key" = "bsp" ]
                    then
                        # remove "push " prefix from value, so that is 5 chars
                        bsp_packet_recipient="${value:5}"
                    
                    elif [ "$key" = "to" ]
                    then
                        bsp_packet_recipient="$value"
                    
                    elif [ "$key" = "from" ]
                    then
                        bsp_packet_from="$value"
                        
                    elif [ "$key" = "date" ]
                    then
                        bsp_packet_date="$value"
                    
                    elif [ "$key" = "encryption-method" ]
                    then
                        bsp_packet_encryption_method="$value"
                    
                    elif [ "$key" = "encryption-key" ]
                    then
                        bsp_packet_encryption_key="$value"
                        
                    else
                        # warning about header key not parsed due to not implemented
                        echo "warning: Header not implemented: $key"
                    fi
                    
                    # from: $__bs_user@$__bs_host
                    # date: $(date --iso-8601)
                    # encryption-key: $(cat "$key_file.enc" | base64 -w 0)
                    # encryption-method: openssl aes-256-cbc
                    
                done <"$header_file"
                
                # end of header here, we must switch to binary mode (although data may also be sent using base64 encoding for human-friendliness)
                
                from_addr=($(parse_address "$bsp_packet_from"))
                contact="${from_addr[0]}@${from_addr[1]}"
                
                # check if we know this contact
                if ! [ -e "$__bs_home/contacts/$contact" ]
                then
                    echo "error: Unknown contact: $contact"
                    echo "hint: Don't worry, this is not your fault, stranger. You may try to register yourself here using: bs add <user@host> $__bs_host"
                    exit 1
                    
                elif ! [ -e "$__bs_home/contacts/$contact/cert.pem" ]
                then
                    echo "error: Certificate not found: $contact/cert.pem"
                    exit 1
                    
                    # this may be automatically resolved using: $0 pull "$contact$contact_port&cert.pem"
                fi
                
                
                # but first we must check the signature
                if [ -n "$signature" ]
                then
                    # create hash
                    header_hash_file="$header_file.hash"
                    if [ "$hash_fn" = "sha256" ] || [ "$hash_fn" = "SHA256" ] || [ "$hash_fn" = "SHA-256" ] || [ "$hash_fn" = "sha-256" ]
                    then
                        cleanup_array+=(rm -f "\"$header_hash_file\"")
                        
                        openssl dgst -sha256 "$header_file" >"$header_hash_file"
                    else
                        echo "error: Unsupported hash: $hash_fn"
                        exit 1
                    fi
                    
                    # verify signature
                    if ! echo "$signature" | base64 -d | openssl rsautl -verify -certin -in "$__bs_home/contacts/$contact/cert.pem" -keyform pem -in "$header_hash_file"
                    then
                        echo "error: Invalid signature."
                        echo "info: For hash: $(cat "$header_hash_file")"
                        echo "info: For cert: $(cat "$__bs_home/contacts/$contact/cert.pem")"
                        exit 1
                    fi
                else
                    echo "error: Signature is mandatory for command: $cmd"
                    echo "hint: Create a hash (sha256) of the '$proto $cmd' header (excluding the blank line before the payload data)."
                    echo "hint: Calculate a signature of the hash using your private key."
                    echo "hint: Prepend a '$proto signature <signature>' header before the '$proto $cmd' header, with a blank line in between the two headers."
                    echo "hint: Provide the used hash function in the '$proto signature <signature>' header (e.g. hash: sha256)."
                    exit 1
                fi
                
                
                # process payload, we cannot and should not decrypt here
                # that must be done by the one who does pull, which is the recipient of this push
                # just write to cache directory for the recipient
                
                recipient=($(parse_address "$bsp_packet_recipient"))
                recipient_contact="${recipient[0]}@${recipient[1]}"
                
                recipient_store_dir="$__bs_home/store/$recipient_contact"
                recipient_contact_dir="$__bs_home/contacts/$recipient_contact"
                
                # check if host matches ours
                if [ "${recipient[1]}" != "$__bs_host" ]
                then
                    conn_host="${recipient[1]}"
                    conn_port="$__bs_default_secure_port"
                    if [ -n "${recipient[2]}" ] && [ "${recipient[2]}" -ne "$__bs_default_secure_port" ]
                    then
                        conn_port="${recipient[2]}"
                    fi
                    
                    # otherwise, we can relay the message to the correct host here
                    echo "info: Relaying from host: $__bs_host"
                    echo "info: Relaying to host: $conn_host:$conn_port"
                    echo "" # blank line to indicate next messages are from the relayed host
                    
                    # relay signature header, packet header, and packet payload
                    cat "$signature_header_file" "$header_file" - | openssl s_client -cert "$__bs_home/cert.pem" -key "$__bs_home/key.pem" -connect "$conn_host:$conn_port"
                    
                    exit 0
                fi
                
                # check if recipient is a contact on the server
                if ! [ -e "$recipient_contact_dir" ]
                then
                    echo "error: Contact not found: $recipient_contact"
                    exit 1
                fi
                
                # automatically create recipient store dir if never sent to this recipient before
                if ! [ -e "$recipient_store_dir" ]
                then
                    mkdir -p "$recipient_store_dir" || { echo "error: Internal server error (mkdir)."; exit 1; }
                fi
                
                recipient_path="${recipient[3]}"
                
                
                if [ "${recipient_path:0:1}" = "&" ]
                then
                    # if &ref, then this is invalid, this is read-only without user in the path, /&ref
                    
                    echo "error: Forbidden to write, path is read-only: $recipient_path"
                    exit 1
                    
                elif [ "${recipient_path:0:1}" = "#" ]
                then
                    # if #channel, then /#channel/user
                    
                    recipient_store_file="$recipient_store_dir/$recipient_path/$recipient_contact"
                    
                    # security check:
                    case "$(readlink -m "$recipient_store_file")" in
                        "$recipient_store_dir/"*) ;;
                        *)
                            echo "error: Forbidden path, out of jail: $recipient_path"
                            exit 1
                        ;;
                    esac
                    
                else
                    # if /path, then /user/path
                    
                    recipient_store_file="$recipient_store_dir/$recipient_contact/$recipient_path"
                    
                    # security check:
                    case "$(readlink -m "$recipient_store_file")" in
                        "$recipient_store_dir/$recipient_contact/"*) ;;
                        *)
                            echo "error: Forbidden path, out of jail: $recipient_path"
                            exit 1
                        ;;
                    esac
                    
                fi
                
                if ! mkdir -p "$recipient_store_file/.."
                then
                    echo "error: Internal server error (mkdir)."
                    exit 1
                fi
                
                cat "$signature_header_file" "$header_file" - >"$recipient_store_file"
                
                # consume signature (reset values for possible next iteration)
                signature_header_file=""
                signature=""
                hash_fn=""
                
            elif [ "$cmd" = "pull" ]
            then
                echo "error: Not yet implemented: $cmd"
                exit 1
                
            elif [ "$cmd" = "list" ]
            then
                echo "error: Not yet implemented: $cmd"
                exit 1
                
            elif [ "$cmd" = "list" ]
            then
                echo "error: Not yet implemented: $cmd"
                exit 1
                
            else
                echo "error: Unsupported command: $cmd"
                exit 1
            fi
        else
            echo "error: Unsupported protocol: $proto"
            exit 1
        fi
    done
fi



### TUTORIAL:
exit 0


# clean up:

rm -Rf /tmp/test*



# init certs and user dirs:

BS_HOME=/tmp/test-bs-user1 ./bs.sh push user2@bs.net
BS_HOME=/tmp/test-bs-user2 ./bs.sh push user1@bs.net



# add each other as contacts

BS_HOME=/tmp/test-bs-user1 ./bs.sh add user2@bs.net /tmp/test-bs-user2/cert.pem
BS_HOME=/tmp/test-bs-user2 ./bs.sh add user1@bs.net /tmp/test-bs-user1/cert.pem


