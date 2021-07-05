#!/bin/bash

# Initialize variables
__bs_home="${BS_HOME:-~/.bs}"
__bs_default_port="2770"
__bs_default_secure_port="2771"
__bs_default_path="#hello"
__bs_default_encryption_method="openssl -aes-256-cbc -pbkdf2 -iter 20000"



parse_address()
{
	__fn_addr="$1"
	
	# separate path which may contain a lot of special chars away from the rest
	__fn_addr_sep="$__fn_addr"
	__fn_addr_sep="${__fn_addr_sep%%:*}"
	__fn_addr_sep="${__fn_addr_sep%%#*}"
	__fn_addr_sep="${__fn_addr_sep%%/*}"
	__fn_addr_sep="${__fn_addr_sep%%&*}"
	
	# parse user:
	if [ "${__fn_addr:0:1}" = "@" ]
	then
		__fn_addr_user="${__fn_addr_sep}"
    else
        __fn_addr_user="@${__fn_addr_sep%%@*}"
	fi
	
	# parse host:
	__fn_addr_host="${__fn_addr_sep:${#__fn_addr_user}}"
	
	# parse port:
	__fn_addr_port="${__fn_addr#*:}"
	__fn_addr_port="${__fn_addr_port%%:*}"
	__fn_addr_port="${__fn_addr_port%%#*}"
	__fn_addr_port="${__fn_addr_port%%/*}"
	__fn_addr_port="${__fn_addr_port%%&*}"
	if [ -n "${__fn_addr_port//[0-9]/}" ]
	then
        __fn_addr_path="$__fn_addr_port"
		__fn_addr_port="$__bs_default_secure_port"
	fi
	
	# parse path:
	__fn_addr_path_offset="${#__fn_addr_sep}"
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
	
	# fix user:
	if [ "${__fn_addr_user:0:1}" = "@" ]
	then
        __fn_addr_user="${__fn_addr_user:1}"
	fi
	
	echo "$__fn_addr_user"
	echo "$__fn_addr_host"
	echo "$__fn_addr_port"
	echo "$__fn_addr_path"
}
pipe_linebuffer()
{
    __fn_blocksize="${1:-16}"
    while IFS= read -r line;do len="${#line}"; len="$(( ($__fn_blocksize - (len + 1) % $__fn_blocksize) % $__fn_blocksize ))"; echo "$line"; printf "%${len}s" | tr ' ' '\0'; done
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

if [ "$1" = "add" ] || [ "$1" = "register" ] || [ "$1" = "deregister" ] # bs add <user@host> [host][:port]
then
	# Add a contact by their public key (in stdin) and address
	
	# TODO: connect to host, and send request to register at server, server may be open to any new contacts and/or users
	# In this case, deregister is only allowed if local connection, or if authenticated through signature matching the contact signature
	# Trash should be regularly deleted by server, using find and mtime +2, for any file >48h old
	
	{ read -r addr_user; read -r addr_host; read -r addr_port; read -r addr_path; } < <(parse_address "$2")
	
	# Check usage
	if [ -z "$addr_user" ] || [ -z "$addr_host" ]
	then
		echo "error: Invalid usage. Use: $0 add <user@host>" >&2
		exit 1
	fi
	
	contact="$addr_user@$addr_host"
	
	# Setup contact directory
	contact_dir="$__bs_home/contacts/$contact"
	if ! [ -e "$contact_dir" ]
	then
		mkdir -p "$contact_dir"
    else
        if [ "$1" = "register" ] && ! [ -e "$__bs_home/store/$contact" ]
        then
            if [ -e "$__bs_home/trash/store/$contact" ]
            then
                mv "$__bs_home/trash/store/$contact" "$__bs_home/store/$contact"
                
                echo "info: Existing user store restored from trash: trash/store/$contact"
            else
                mkdir -p "$__bs_home/store/$contact"
            fi
            echo "info: Existing contact successfully registered as user: $contact"
            exit 0
        elif [ "$1" = "deregister" ]
        then
            if [ -e "$__bs_home/store/$contact" ]
            then
                if ! [ -e "$__bs_home" ]
                then
                    mkdir -p "$__bs_home/trash/store"
                fi
                
                mv "$__bs_home/store/$contact" "$__bs_home/trash/store/$contact"
                
                echo "info: Existing store directory put in trash: trash/store/$contact"
            fi
            echo "info: Existing user successfully deregistered, is now a contact: $contact"
            exit 0
        else
            echo "error: Contact already exists: $contact"
            exit 1
        fi
	fi
	
	# Write public-key to contact file
	cat "${3:---}" > "$contact_dir/cert.pem"
	
	# Write custom port to contact file
	if [ -n "$addr_port" ]
	then
		echo "$addr_port" > "$contact_dir/port"
	fi
	
	# Maybe also create a store directory, if this user is to be registered as a user instead of contact
	if [ "$1" = "register" ]
	then
        mkdir -p "$__bs_home/store/$contact"
        
        echo "info: New user successfully registered: $contact"
    else
        echo "info: New contact successfully added: $contact"
	fi

elif [ "$1" = "push" ] # bs push --line-buffered --block-size 16 <user@host> [host][:port]
then
	# Connect to the target host or override host with another service
	
	blocksize="16"
	is_line_buffered=false
	while true
	do
        if [ "$2" == "--line-buffered" ]
        then
            echo "info: Line buffered"
            is_line_buffered=true
            shift 1
            
        elif [ "$2" == "--block-size" ]
        then
            blocksize="$3"
            echo "info: Block size: $blocksize"
            shift 2
        else
            break
        fi
	done
	
	cleanup_array=()
    cleanup()
    {
        for cmd in "${cleanup_array[@]}"
        do
            $cmd
        done
    }
    trap 'cleanup' EXIT
	
	{ read -r target_addr_user; read -r target_addr_host; read -r target_addr_port; read -r target_addr_path; } < <(parse_address "$2")
	{ read -r connect_addr_user; read -r connect_addr_host; read -r connect_addr_port; read -r connect_addr_path; } < <(parse_address "$3")
    
    conn_host="$target_addr_host"
	conn_port="$target_addr_port"
	if [ -n "$connect_addr_host" ]
	then
		conn_host="$connect_addr_host"
	fi
	if [ -n "$connect_addr_port" ]
	then
		conn_port="$connect_addr_port"
	fi
	
    contact="$target_addr_user@$target_addr_host"
    
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
	
	# Build the header
	header_file="$__bs_home/.tmp-header.$(date +'%s%N').txt"
	cleanup_array+=("rm -f \"$header_file\"")
	cat <<EOF >"$header_file"
bsp push $2
from: $__bs_user@$__bs_host
date: $(date --iso-8601)
EOF
    
    if [ -n "$__bs_default_encryption_method" ]
    then
        # Generate a symmetric encryption key
        key_file="$__bs_home/.tmp-random.$(date +'%s%N').bin"
        cleanup_array+=("rm -f \"$key_file\"")
        openssl rand -base64 32 >"$key_file"
        
        # Encrypt the symmetric encryption key
        cleanup_array+=("rm -f \"$key_file.enc\"")
        openssl rsautl -encrypt -certin -inkey "$__bs_home/contacts/$contact/cert.pem" -in "$key_file" -out "$key_file.enc"
        
        cat <<EOF >>"$header_file"
encryption-method: $__bs_default_encryption_method
encryption-key: $(cat "$key_file.enc" | base64 -w 0)
EOF
    fi
    
    # Create signature of header
    header_hash_file="$header_file.sha256"
    cleanup_array+=("rm -f \"$header_hash_file\"")
    openssl dgst -binary -sha256 "$header_file" >"$header_hash_file"
	
	# Securely connect with the conn_host:conn_port
	{
        # Send header signature:
        echo -n "bsp signature "
        openssl rsautl -sign -inkey "$__bs_home/key.pem" -keyform pem -in "$header_hash_file" | base64 -w 0 && echo
        echo "hash: sha256"
        
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
        if [ "${__bs_default_encryption_method:0:8}" = "openssl " ]
        then
            # stdbuf --output=L 
            if $is_line_buffered
            then
                pipe_linebuffer "$blocksize" | stdbuf --output=0 openssl enc ${__bs_default_encryption_method:8} -bufsize 16 -kfile "$key_file"
            else
                stdbuf --output=0 openssl enc ${__bs_default_encryption_method:8} -bufsize 16 -kfile "$key_file"
            fi
        else
            stdbuf --output=L cat
        fi
        
        # -no_ign_eof -> close on end of stdin
    } | openssl s_client -cert "$__bs_home/cert.pem" -key "$__bs_home/key.pem" -connect "$conn_host:$conn_port" -quiet -crlf -no_ign_eof 
	
	
elif [ "$1" = "pull" ] # bs pull <path>
then
    
    cleanup_array=()
    cleanup()
    {
        for cmd in "${cleanup_array[@]}"
        do
            $cmd
        done
    }
    trap 'cleanup' EXIT
    
    # bs pull should retrieve a complete directory listing of non-empty files on the server
    # basically:
    #  - #channel1 -> store/user/#channel1/some-user@some-host
    #  - #channel2 -> store/user/#channel2/some-user@some-host
    #  - /any/path/to/anywhere -> store/user/some-user@some-host/any/path/to/anywhere
    #  - &cert.pem -> contacts/user/cert.pem
    
    conn_host="$(cat "$__bs_home/host")"
    conn_port="$__bs_default_secure_port"
    if [ -e "$__bs_home/port" ]
    then
        conn_port="$(cat "$__bs_home/port")"
    fi
    
    echo "Connecting to $conn_host:$conn_port"
    
    conn_dir="$__bs_home/contacts/$conn_host"
    
    # Grab the public certificate of the remote server
    if ! [ -e "$conn_dir" ]
    then
        mkdir -p "$conn_dir"
    fi
    conn_cert="$conn_dir/cert.pem"
    if ! [ -e "$conn_cert" ]
    then
        echo "Grabbing server public certificate"
        openssl s_client -servername "$conn_host" -showcerts "$conn_host:$conn_port" 2>/dev/null | openssl x509 >"$conn_cert"
    fi
    
	# Build the header
	header_file="$__bs_home/.tmp-header.$(date +'%s%N').txt"
	cleanup_array+=("rm -f \"$header_file\"")
	cat <<EOF >"$header_file"
bsp pull $2
from: $__bs_user@$__bs_host
date: $(date --iso-8601)
EOF
    
    # Create signature of header
    header_hash_file="$header_file.sha256"
    cleanup_array+=("rm -f \"$header_hash_file\"")
    openssl dgst -binary -sha256 "$header_file" >"$header_hash_file"
	
	# Securely connect with the conn_host:conn_port
	{
        # Send header signature:
        echo -n "bsp signature "
        openssl rsautl -sign -inkey "$__bs_home/key.pem" -keyform pem -in "$header_hash_file" | base64 -w 0 && echo
        echo "hash: sha256"
        
        # Send blank line before next header
        echo ""
        
        # Send header:
        cat "$header_file"
        
        # Send blank line before data payload:
        echo ""
        
        # No payload, we already sent the path we want to pull
        
    } | openssl s_client -cert "$__bs_home/cert.pem" -key "$__bs_home/key.pem" -CAfile "$conn_cert" -connect "$conn_host:$conn_port" -quiet -crlf | "$0" accept-local

elif [ "$1" = "listen" ]
then
    
    { read -r bind_addr_user; read -r bind_addr_host; read -r bind_addr_port; read -r bind_addr_path; } < <(parse_address "$2")
    
    # listen, receive push/pull requests
    # store push in local filesystem
    
    #if [ "$bind_port" = "$__bs_default_secure_port" ]
    #then
    #    bind_port="$__bs_default_secure_port"
    #fi
    
    # listen daemon must regularly delete trash using find mtime +2 (>48h)
    
    echo "Listening at ${bind_addr_host:-127.0.0.1}:${bind_addr_port:-$__bs_default_secure_port} for connections..."
    
    ncat --ssl --ssl-cert "$__bs_home/cert.pem" --ssl-key "$__bs_home/key.pem" -k -l -c "$0 accept" "${bind_addr_host:-127.0.0.1}" "${bind_addr_port:-$__bs_default_secure_port}"
    
    
elif [ "$1" = "accept" ] || [ "$1" = "accept-local" ]
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
    
    is_local=false
    if [ "$1" = "accept-local" ]
    then
        is_local=true
    fi
    
    echo "debug: connection accepted ($1)"
    
    while IFS=$'\r ' read -r proto cmd _value
    do
        value="${_value%$'\r'}"
        
        # echo "debug: read $proto $cmd $value"
        
        if [ "$proto" = "bsp" ]
        then
            # careful, value may not have additional spaces at the beginning or end, or the signature will fail, due to trimming by read
            header_file="$__bs_home/.tmp-header.$(date +'%s%N').txt"
            header_file_crlf="$__bs_home/.tmp-header-crlf.$(date +'%s%N').txt"
            
            cleanup_array+=("rm -f \"$header_file\"")
            cleanup_array+=("rm -f \"$header_file_crlf\"")
            
            echo "debug: reading header..."
            
            echo "$proto $cmd $value" >"$header_file"
            echo "$proto $cmd $value"$'\r' >"$header_file_crlf"
            while IFS=$'\r ' read -r _line
            do
                line="${_line%$'\r'}"
                
                if [ -z "$line" ]
                then
                    break
                fi
                
                # read raw lines first, otherwise spaces may have been trimmed off, and we would be unable to reliably generate the same hash for the signature
                echo "$line" >>"$header_file"
                echo "$line"$'\r' >>"$header_file_crlf"
            done
            
            echo "debug: header read"
            
            if [ "$cmd" = "signature" ]
            then
                echo "debug: command signature ..."
            
                signature_header_file="$header_file"
                signature="$value"
                hash_fn="sha256"
                
                while IFS=$'\r :' read -r key value
                do
                    if [ -z "$key" ]
                    then
                        echo "debug: End of header"
                        break
                    fi
                    
                    echo "debug: Header entry found: $key = $value"
                    
                    if [ "$key" = "bsp" ]
                    then
                        continue
                    elif [ "$key" = "hash" ]
                    then
                        hash_fn="$value"
                        
                    elif [ "$key" = "value" ] || [ "$key" = "signature" ]
                    then
                        signature="$value"
                    
                    fi
                done <"$header_file"
                
                echo "end of signature packet"
            
            elif [ "$cmd" = "list" ]
            then
                echo "STDERR:" >&2
                cat "$header_file" >&2
                echo "" >&2
                
                echo "STDOUT:"
                
                cat
            
            elif [ "$cmd" = "push" ] || [ "$cmd" = "pull" ]
            then
                
                echo "debug: command $cmd $value"
                
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
                    
                done <"$header_file"
                
                # end of header here, we must switch to binary mode (although data may also be sent using base64 encoding for human-friendliness)
                
                { read -r from_addr_user; read -r from_addr_host; read -r from_addr_port; read -r from_addr_path; } < <(parse_address "$bsp_packet_from")
                contact="$from_addr_user@$from_addr_host"
                
                # check if we know this contact
                if ! [ -e "$__bs_home/contacts/$contact" ]
                then
                    echo "error: Unknown contact: $contact"
                    echo "hint: Don't worry, this is not your fault, stranger. You may try to register yourself here using: bs {add|register} <user@host> $__bs_host"
                    exit 1
                    
                elif ! [ -e "$__bs_home/contacts/$contact/cert.pem" ]
                then
                    echo "error: Certificate not found: $contact/cert.pem"
                    exit 1
                    
                    # this may be automatically resolved using: $0 pull "$contact$contact_port&cert.pem"
                fi
                
                { read -r recipient_addr_user; read -r recipient_addr_host; read -r recipient_addr_port; read -r recipient_addr_path; } < <(parse_address "$bsp_packet_recipient")
                
                recipient_contact="$recipient_addr_user@$recipient_addr_host"
                recipient_path="$recipient_addr_path"
                
                echo "debug: recipient: $recipient_addr_path"
                
                # but first we must check the signature
                if [ -n "$signature" ]
                then
                    # create hash
                    header_hash_file="$header_file.hash"
                    header_hash_file_crlf="$header_file_crlf.hash"
                    
                    echo "debug: checking signature"
                    
                    if [ "$hash_fn" = "sha256" ] || [ "$hash_fn" = "SHA256" ] || [ "$hash_fn" = "SHA-256" ] || [ "$hash_fn" = "sha-256" ]
                    then
                        cleanup_array+=("rm -f \"$header_hash_file\"")
                        openssl dgst -binary -sha256 "$header_file" | base64 -w 0 >"$header_hash_file"
                        
                        cleanup_array+=("rm -f \"$header_hash_file_crlf\"")
                        openssl dgst -binary -sha256 "$header_file_crlf" | base64 -w 0 >"$header_hash_file_crlf"
                        
                    else
                        echo "error: Unsupported hash: $hash_fn"
                        exit 1
                    fi
                    
                    # verify signature, decrypts signature to recover hash
                    decrypted_hash="$(echo "$signature" | base64 -d | openssl rsautl -verify -certin -inkey "$__bs_home/contacts/$contact/cert.pem" -keyform pem | base64 -w 0)"
                    
                    if [ "$decrypted_hash" != "$(cat "$header_hash_file")" ] && [ "$decrypted_hash" != "$(cat "$header_hash_file_crlf")" ]
                    then
                        echo "error: Invalid signature."
                        echo "info: For hash: $(cat "$header_hash_file" | base64 -w 0)"
                        echo "info: For cert: $(cat "$__bs_home/contacts/$contact/cert.pem")"
                        exit 1
                    else
                        echo "debug: signature is ok"
                    fi
                    
                elif [ "$cmd" = "push" ] || [ "${recipient_path:0:1}" != "&" ]
                then
                    echo "error: Signature is mandatory for command: $cmd"
                    echo "hint: Create a hash (sha256) of the '$proto $cmd' header (excluding the blank line before the payload data)."
                    echo "hint: Calculate a signature of the hash using your private key."
                    echo "hint: Prepend a '$proto signature <signature>' header before the '$proto $cmd' header, with a blank line in between the two headers."
                    echo "hint: Provide the used hash function in the '$proto signature <signature>' header (e.g. hash: sha256)."
                    exit 1
                else
                    echo "debug: skipping signature, not required"
                fi
                
                if $is_local
                then
                    
                    # write header info to stderr, and then decrypted body to stdout
                    
                    if [ "$cmd" = "push" ]
                    then
                        cat "$signature_header_file" >&2
                        echo "" >&2
                        cat "$header_file" >&2
                        echo "" >&2
                        
                        pipeline=""
                        
                        key_file="$__bs_home/.tmp-encryption-key.$(date +'%s%N').bin"
                        cleanup_array+=("rm -f \"$key_file\"")
                        if [ -n "$bsp_packet_encryption_key" ]
                        then
                            echo "$bsp_packet_encryption_key" | base64 -d | openssl rsautl -decrypt -inkey "$__bs_home/key.pem" >"$key_file"
                        fi
                        
                        if [ -n "$bsp_packet_encryption_method" ]
                        then
                            if [ "${bsp_packet_encryption_method:0:8}" = "openssl " ]
                            then
                                if [ -n "$pipeline" ]
                                then
                                    pipeline="$pipeline | "
                                fi
                                
                                pipeline="${pipeline}stdbuf --output=0 openssl enc -d ${bsp_packet_encryption_method:8} -bufsize 16 -kfile \"$key_file\""
                            else
                                echo "error: Unsupported encryption method: $bsp_packet_encryption_method"
                                exit 1
                            fi
                        fi
                        
                        if [ -n "$bsp_packet_compression_method" ]
                        then
                            if [ "$bsp_packet_compression_method" = "gzip" ] || [ "$bsp_packet_compression_method" = "gz" ]
                            then
                                if [ -n "$pipeline" ]
                                then
                                    pipeline="$pipeline | "
                                fi
                                pipeline="${pipeline}gzip -d"
                            else
                                echo "error: Unsupported compression method: $bsp_packet_compression_method"
                                exit 1
                            fi
                        fi
                        
                        # no decryption or filter needed
                        cat | bash -c "$(echo "$pipeline")"
                        
                    else
                        echo "warning: Cannot handle command locally: $cmd" >&2
                    fi
                    
                else
                    if [ "$cmd" = "push" ]
                    then
                        recipient_store_dir="$__bs_home/store/$recipient_contact"
                        recipient_contact_dir="$__bs_home/contacts/$recipient_contact"
                    
                        # check if host matches ours
                        if [ "$recipient_addr_host" != "$__bs_host" ]
                        then
                            conn_host="$recipient_addr_host"
                            conn_port="${recipient_addr_port:-$__bs_default_secure_port}"
                            
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
                            echo "error: Recipient does not have a storage directory ($recipient_contact)."
                            exit 1
                        fi
                        
                        if [ -z "$recipient_path" ]
                        then
                            recipient_path="$__bs_default_path"
                        fi
                        
                        if [ "${recipient_path:0:1}" = "&" ]
                        then
                            # if &ref, then this is invalid, this is read-only without user in the path, /&ref
                            
                            echo "error: Forbidden to write, path is read-only: $recipient_path"
                            exit 1
                            
                        elif [ "${recipient_path:0:1}" = "#" ]
                        then
                            # if #channel, then /#channel/user
                            
                            # filter #channel/some/path to #channel-some-path
                            recipient_path="${recipient_path//\//-}"
                            
                            recipient_store_file="$recipient_store_dir/$recipient_path/$contact.$(date +'%s%N')"
                            
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
                            
                            recipient_store_file="$recipient_store_dir/$contact/$recipient_path.$(date +'%s%N')"
                            
                            # security check:
                            case "$(readlink -m "$recipient_store_file")" in
                                "$recipient_store_dir/$recipient_contact/"*) ;;
                                *)
                                    echo "error: Forbidden path, out of jail: $recipient_path"
                                    exit 1
                                ;;
                            esac
                            
                        fi
                        
                        if ! mkdir -p "$(readlink -m "$recipient_store_file/..")"
                        then
                            echo "error: Internal server error (mkdir)."
                            exit 1
                        fi
                        
                        tmp_store_file="$__bs_home/.tmp-store.$(date +'%s%N').bin"
                        cleanup_array=("rm -f \"$tmp_store_file\"")
                        
                        # prepare headers in tmp file
                        cat "$signature_header_file" >"$tmp_store_file"
                        echo "" >>"$tmp_store_file"
                        cat "$header_file" >>"$tmp_store_file"
                        echo "" >>"$tmp_store_file"
                        
                        # append headers and then stdin to file
                        cat "$tmp_store_file" - >"$recipient_store_file"
                    
                    elif [ "$cmd" = "pull" ]
                    then
                        # search the from-user directory
                        
                        contact_dir="$__bs_home/store/$contact"
                        contact_store_file=""
                        
                        # default to reading from own user directory (self)
                        if [ -z "$recipient_contact" ] || [ "$recipient_contact" = "@" ]
                        then
                            recipient_contact="$contact"
                        fi
                        
                        if [ "${recipient_path:0:1}" = "&" ]
                        then
                            # this is a public dir, anyone, without signature can request this
                            # this is how cert.pem is distributed, for instance
                            
                            if [ "$recipient_path" = "cert.pem" ]
                            then
                                cat "$__bs_home/contacts/$contact/cert.pem"
                                exit 0
                            else
                                echo "info: Path not found: $recipient_path"
                                exit 0
                            fi
                        
                        elif [ "${recipient_path:0:1}" = "#" ]
                        then
                            contact_store_file="$contact_dir/$recipient_path"
                            
                        elif [ -z "$recipient_path" ]
                        then
                            # list channels and users that wrote stuff etc
                            contact_store_file="$contact_dir"
                        else
                            contact_store_file="$contact_dir/$recipient_contact/$recipient_path"
                        fi
                        
                        # security check:
                        case "$(readlink -m "$contact_store_file")" in
                            "$contact_dir/"*) ;;
                            "$contact_dir"*) ;;
                            *)
                                echo "error: Forbidden path, out of jail: $recipient_path"
                                exit 1
                            ;;
                        esac
                        
                        contact_store_file="$(readlink -m "$contact_store_file")"
                        
                        echo "debug: reading path: $contact_store_file"
                        
                        # send blank line before the actual data payload
                        # this way we can send warning/error/info/debug messages before the payload, which should be skipped by the receiver
                        echo ""
                        
                        if [ -f "$contact_store_file" ]
                        then
                            # print file contents
                            cat "$contact_store_file"
                        else
                            # list directory (no particular order, 1 file per line, escape non-printable characters)
                            echo "bsp list ${recipient_path:${#contact_dir}}"
                            echo ""
                            ls -U -1 -b "$contact_store_file"
                        fi
                        
                        # don't exit, to allow multiple requests in the same connection
                        exit 0
                    else
                        echo "info: Unknown command: $cmd"
                    fi
                fi
                
                # consume signature (reset values for possible next iteration)
                signature_header_file=""
                signature=""
                hash_fn=""
                
            else
                echo "error: Unsupported command: $cmd"
                exit 1
            fi
        else
            echo "warning: Unsupported protocol: $proto"
            
            # wait until empty line, then we check protocol again
            while IFS=$'\r ' read -r _line
            do
                line="${_line%$'\r'}"
                
                if [ -z "$line" ]
                then
                    break
                fi
            done
            
            # check protocol again in next round
        fi
    done
    
    echo "debug: connection ended"
    
fi



### TUTORIAL:
exit 0


# clean up:

rm -Rf /tmp/test*



# init certs and user dirs:

BS_HOME=/tmp/test-bs-alice ./bs.sh push bob@bs.net
BS_HOME=/tmp/test-bs-bob ./bs.sh push alice@bs.net


# set correct host:

echo "bs.net" >/tmp/test-bs-alice/host
echo "bs.net" >/tmp/test-bs-bob/host

# set correct user:

echo "alice" >/tmp/test-bs-alice/user
echo "bob" >/tmp/test-bs-bob/user

# add self as contact and user

BS_HOME=/tmp/test-bs-alice ./bs.sh register alice@bs.net /tmp/test-bs-alice/cert.pem
BS_HOME=/tmp/test-bs-bob ./bs.sh register bob@bs.net /tmp/test-bs-bob/cert.pem

# add each other as contacts

BS_HOME=/tmp/test-bs-alice ./bs.sh add bob@bs.net /tmp/test-bs-bob/cert.pem
BS_HOME=/tmp/test-bs-bob ./bs.sh add alice@bs.net /tmp/test-bs-alice/cert.pem



# to deal with aes-256-cbc plain text messages, we need to ensure every line to match 16 byte buffer length (for the block size of AES-256 bits = 32 bytes)

while IFS= read -r line;do len="${#line}"; len="$(( (16 - (len + 1) % 16) % 16 ))"; echo "$line"; printf "%${len}s" | tr ' ' '\0'; done

