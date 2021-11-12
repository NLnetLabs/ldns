#!/usr/bin/env bash

#
# Build a LDNS distribution tar from the GIT repository.
# Ripped from NSD. Adapted by Miek. Adapted by Willem
#

# Abort script on unexpected errors.
set -e

# Remember the current working directory.
cwd=$(pwd)

# Utility functions.
usage () {
    cat >&2 <<EOF
Usage $0: [-h] [-s] [-c <tag/branch>]
Generate a distribution tar file for libdns.

    -h           This usage information.
    -s           Build a snapshot distribution file.  The current date is
                 automatically appended to the current ldns version number.
    -rc <nr>     Build a release candidate, the given string will be added
                 to the version number 
                 (which will then be ldns-<version>rc<number>)
    -c <tag/br>  Checkout this tag or branch (defaults to current branch).
EOF
    exit 1
}

info () {
    echo "$0: info: $1"
}

error () {
    echo "$0: error: $1" >&2
    exit 1
}

question () {
    printf "%s (y/n) " "$*"
    read -r answer
    case "$answer" in
        [Yy]|[Yy][Ee][Ss])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Only use cleanup and error_cleanup after generating the temporary
# working directory.
cleanup () {
    info "Deleting temporary working directory."
    cd "$cwd" && rm -rf "$temp_dir" && rm -rf "$doc_dir"
}

error_cleanup () {
    echo "$0: error: $1" >&2
    cleanup
    exit 1
}

replace_text () {
    (cp "$1" "$1".orig && \
        sed -e "s/$2/$3/g" < "$1".orig > "$1" && \
        rm "$1".orig) || error_cleanup "Replacement for $1 failed."
}

replace_all () {
    info "Updating '$1' with the version number."
    replace_text "$1" "@version@" "$version"
    info "Updating '$1' with today's date."
    replace_text "$1" "@date@" "$(date +'%b %e, %Y')"
}
    
CHECKOUT=""
SNAPSHOT="no"
RC="no"

# Parse the command line arguments.
while [ "$1" ]; do
    case "$1" in
        "-h")
            usage
            ;;
        "-c")
            CHECKOUT="$2"
            shift
            ;;
        "-s")
            SNAPSHOT="yes"
            ;;
        "-rc")
            RC="$2"
            shift
            ;;
        *)
            error "Unrecognized argument -- $1"
            ;;
    esac
    shift
done

if [ -z "$CHECKOUT" ]
then
	if [ "$RC" = "no" ]
	then
		CHECKOUT=$( (git status | head -1 | awk '{print$3}') || echo master)
	else
		CHECKOUT=$( (git status | head -1 | awk '{print$3}') || echo develop)
	fi
fi

# Start the packaging process.
info "SNAPSHOT is $SNAPSHOT"

#question "Do you wish to continue with these settings?" || error "User abort."


# Creating temp directory
info "Creating temporary working directory"
temp_dir=$(mktemp -d ldns-dist-XXXXXX)
doc_dir=$(mktemp -d ldns-dist-XXXXXX)
info "Directory '$temp_dir' created."
cd "$temp_dir"

info "Exporting source from GIT"
git clone https://github.com/NLnetLabs/ldns.git || error_cleanup "git command failed"
cd ldns || error_cleanup "LDNS not exported correctly from git"
git checkout "$CHECKOUT" || error_cleanup "Could not checkout $CHECKOUT"
git submodule update --init || error_cleanup "Could not update submodules"
(cd contrib/DNS-LDNS; git checkout master) || error_cleanup "Could not checkout DNS-LDNS contribution"

info "Running  Libtoolize script (libtoolize)."
[ -f ../../install-sh ] && mv ../../install-sh ../../install-sh.bak
libtoolize -c --install || libtoolize -c || error_cleanup "Libtoolize failed."
[ -f ../../install-sh.bak ] && mv ../../install-sh.bak ../../install-sh

# Allow libtool to install the distro's config.guess and config.sub. It avoids a pesky
# error message. After libtool is finished, update the scripts from Savannah. This step
# is useful for downlevel clients like OS X and Solaris (and existing scripts with bugs).
info "Fetching latest config.guess and config.sub"
wget -q -O config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD' || error_cleanup "Failed to fetch config.guess"
wget -q -O config.sub 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD' || error_cleanup "Failed to fetch config.sub"
chmod a+x config.guess config.sub

info "Building configure script (autoconf)."
autoreconf -vfi || error_cleanup "Autoconf failed."

rm -r autom4te* || error_cleanup "Failed to remove autoconf cache directory." 

# custom removes
find . -name .c-mode-rc.el -exec rm {} \;
find . -name .cvsignore -exec rm {} \;
rm  -f .gitignore .gitmodules contrib/DNS-LDNS/.git .travis.yml .gitlab-ci.yml
rm -rf .git .github
rm -rf lua 
rm -rf masterdont 
rm makedist.sh || error_cleanup "Failed to remove makedist.sh."

info "Determining LDNS version."
version=$(./configure --version | head -1 | awk '{ print $3 }') || \
    error_cleanup "Cannot determine version number."
( cd contrib/DNS-LDNS; dzil build && mv -v DNS-LDNS-*.tar.gz .. )
perl_tarball="$(cd contrib; echo DNS-LDNS-*.tar.gz)"
perl_version="${perl_tarball%.tar.gz}"
perl_version="${perl_version#DNS-LDNS-}"
( cd contrib				&&
  rm -fr DNS-LDNS			&&
  tar xzvf "$perl_tarball"		&&
  mv "DNS-LDNS-$perl_version" DNS-LDNS	&&
  rm -f "$perl_tarball"			 )
info "LDNS version: $version"
info "DNS-LDNS perl module version: $perl_version"

RECONFIGURE="no"

if [ "$RC" != "no" ]; then
    info "Building LDNS release candidate $RC."
    version2="${version}-rc.$RC"
    info "Version number: $version2"

    replace_text "configure.ac" "AC_INIT(ldns, $version" "AC_INIT(ldns, $version2"
    version="$version2"
    RECONFIGURE="yes"
fi

if [ "$SNAPSHOT" = "yes" ]; then
    info "Building LDNS snapshot."
    version2="${version}_$(date +%Y%m%d)"
    info "Snapshot version number: $version2"

    replace_text "configure.ac" "AC_INIT(ldns, $version" "AC_INIT(ldns, $version2"
    version="$version2"
    RECONFIGURE="yes"
fi

if [ "$RECONFIGURE" = "yes" ]; then
    info "Rebuilding configure script (autoconf)."
    autoreconf -vfi || error_cleanup "Autoconf failed."

    rm -r autom4te* || error_cleanup "Failed to remove autoconf cache directory."
fi


info "Renaming LDNS directory to ldns-$version."
cd ..
mv ldns ldns-"$version" || error_cleanup "Failed to rename LDNS directory."

info "Building the manpages"
(
 	srcdir=$(pwd)
	cd "../$doc_dir"
	"${srcdir}/ldns-$version/configure" --disable-dane
	make manpages
	cp -prv doc/ldns_manpages "${srcdir}/ldns-$version/doc/ldns_manpages"
	cp -prv doc/man "${srcdir}/ldns-$version/doc/man"
)

tarfile="../ldns-$version.tar.gz"

if [ -f "$tarfile" ]; then
    (question "The file $tarfile already exists.  Overwrite?" \
        && rm -f "$tarfile") || error_cleanup "User abort."
fi

info "Deleting the test directory"
rm -rf "ldns-$version/test/"

info "Deleting the pcat directory"
rm -rf "ldns-$version/pcat/"

info "Deleting the nsd-test directory"
rm -rf "ldns-$version/examples/nsd-test/"

info "Creating tar ldns-$version.tar.gz"
tar czf "../ldns-$version.tar.gz" "ldns-$version" || error_cleanup "Failed to create tar file."

cleanup

echo "ostype $OSTYPE"
case $OSTYPE in
        linux*)
                sha=$(sha1sum "ldns-$version.tar.gz" |  awk '{ print $1 }')
                sha2=$(sha256sum "ldns-$version.tar.gz" |  awk '{ print $1 }')
                ;;
        freebsd*)
                sha=$(sha1  "ldns-$version.tar.gz" |  awk '{ print $5 }')
                sha2=$(sha256  "ldns-$version.tar.gz" |  awk '{ print $4 }')
                ;;
        *)
        	uname=$(uname)
        	case $uname in
        		Linux*)
                        	sha=$(sha1sum "ldns-$version.tar.gz" | awk '{ print $1 }')
                		sha2=$(sha256sum "ldns-$version.tar.gz" | awk '{ print $1 }')
                        	;;
		        FreeBSD*)
                		sha=$(sha1 "ldns-$version.tar.gz" | awk '{ print $4 }')
                		sha2=$(sha256 "ldns-$version.tar.gz" | awk '{ print $4 }')
		                ;;
		esac
        	;;
esac
echo "$sha" > "ldns-$version.tar.gz.sha1"
echo "$sha2" > "ldns-$version.tar.gz.sha256"
gpg --armor --detach-sig "ldns-$version.tar.gz"

info "LDNS distribution created successfully."
info "SHA1sum: $sha"
