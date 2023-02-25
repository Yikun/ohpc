#
# Copyright (c) Contributors to the Apptainer project, established as
#   Apptainer a Series of LF Projects LLC.
#   For website terms of use, trademark policy, privacy policy and other
#   project policies see https://lfprojects.org/policies
# Copyright (c) 2017-2022, SyLabs, Inc. All rights reserved.
# Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
#
# Copyright (c) 2015-2017, Gregory M. Kurtzer. All rights reserved.
#
# Copyright (c) 2016, The Regents of the University of California, through
# Lawrence Berkeley National Laboratory (subject to receipt of any required
# approvals from the U.S. Dept. of Energy).  All rights reserved.
#
# This software is licensed under a customized 3-clause BSD license.  Please
# consult LICENSE file distributed with the sources of this project regarding
# your rights to use or distribute this software.
#
# NOTICE.  This Software was developed under funding from the U.S. Department of
# Energy and the U.S. Government consequently retains certain rights. As such,
# the U.S. Government has been granted for itself and others acting on its
# behalf a paid-up, nonexclusive, irrevocable, worldwide license in the Software
# to reproduce, distribute copies to the public, prepare derivative works, and
# perform publicly and display publicly, and to permit other to do so.
#
#
 
# Disable debugsource packages; otherwise it ends up with an empty %%files
#   file in debugsourcefiles.list on Fedora
%undefine _debugsource_packages
 
# This can be slightly different than %%{version}.
# For example, it has dash instead of tilde for release candidates.
%global package_version 1.1.6
 
# Uncomment this to include a multithreaded version of squashfuse_ll
%global squashfuse_version 0.1.105
 
# The last singularity version number in EPEL/Fedora
%global last_singularity_version 3.8.7-3
 
Summary: Application and environment virtualization formerly known as Singularity
Name: apptainer
Version: 1.1.6
Release: 1%{?dist}
# See LICENSE.md for first party code (BSD-3-Clause and LBNL BSD)
# See LICENSE_THIRD_PARTY.md for incorporated code (ASL 2.0)
# See LICENSE_DEPENDENCIES.md for dependencies
# License identifiers taken from: https://fedoraproject.org/wiki/Licensing
License: BSD and LBNL BSD and ASL 2.0
URL: https://apptainer.org
Source0: https://github.com/%{name}/%{name}/releases/download/v%{package_version}/%{name}-%{package_version}.tar.gz
 
Patch0: openEuler-golang-1.17.3.patch

%if "%{?squashfuse_version}" != ""
Source10: https://github.com/vasi/squashfuse/archive/%{squashfuse_version}/squashfuse-%{squashfuse_version}.tar.gz
Patch10: 70.patch
Patch11: 77.patch
Patch12: 81.patch
%endif
 
# This Conflicts is in case someone tries to install the main apptainer
# package when an old singularity package is installed.  An Obsoletes is on
# the apptainer-suid subpackage below.  If an Obsoletes were here too, it
# would get different behavior with yum and dnf: a "yum install apptainer"
# on EL7 would install only apptainer but a "dnf install apptainer" on EL8
# or greater would install both apptainer and apptainer-suid.  With this
# Conflicts, both yum and dnf consistently install both apptainer and
# apptainer-suid when apptainer is requested while singularity is installed.
Conflicts: singularity <= %{last_singularity_version}
 
# In the singularity 2.x series there was a singularity-runtime package
#  that could have been installed independently, but starting in 3.x
#  there was only one package
Obsoletes: singularity-runtime < 3.0
 
# Multiple packages contain /usr/bin/singularity and /usr/bin/run-singularity,
# which are necessary to run SIF images.  Use a pivot provides/conflicts to
# avoid them all needing to conflict with each other.
Provides: sif-runtime
Conflicts: sif-runtime
 
Provides: bundled(golang(github.com/AdamKorcz/go_fuzz_headers)) = v0.0.0_20210319161527_f761c2329661
Provides: bundled(golang(github.com/Azure/go_ansiterm)) = v0.0.0_20210617225240_d185dfc1b5a1
Provides: bundled(golang(github.com/BurntSushi/toml)) = v1.2.0
Provides: bundled(golang(github.com/Microsoft/go_winio)) = v0.5.2
Provides: bundled(golang(github.com/Microsoft/hcsshim)) = v0.9.4
Provides: bundled(golang(github.com/Netflix/go_expect)) = v0.0.0_20220104043353_73e0943537d2
Provides: bundled(golang(github.com/ProtonMail/go_crypto)) = v0.0.0_20220824120805_4b6e5c587895
Provides: bundled(golang(github.com/VividCortex/ewma)) = v1.2.0
Provides: bundled(golang(github.com/acarl005/stripansi)) = v0.0.0_20180116102854_5a71ef0e047d
Provides: bundled(golang(github.com/adigunhammedolalekan/registry_auth)) = v0.0.0_20200730122110_8cde180a3a60
Provides: bundled(golang(github.com/alexflint/go_filemutex)) = v1.1.0
Provides: bundled(golang(github.com/apex/log)) = v1.9.0
Provides: bundled(golang(github.com/apptainer/container_key_client)) = v0.8.0
Provides: bundled(golang(github.com/apptainer/container_library_client)) = v1.3.4
Provides: bundled(golang(github.com/apptainer/sif/v2)) = v2.8.1
Provides: bundled(golang(github.com/beorn7/perks)) = v1.0.1
Provides: bundled(golang(github.com/blang/semver)) = v3.5.1+incompatible
Provides: bundled(golang(github.com/blang/semver/v4)) = v4.0.0
Provides: bundled(golang(github.com/buger/jsonparser)) = v1.1.1
Provides: bundled(golang(github.com/bugsnag/bugsnag_go)) = v1.5.1
Provides: bundled(golang(github.com/bugsnag/panicwrap)) = v1.2.0
Provides: bundled(golang(github.com/cenkalti/backoff/v4)) = v4.1.3
Provides: bundled(golang(github.com/cespare/xxhash/v2)) = v2.1.2
Provides: bundled(golang(github.com/cilium/ebpf)) = v0.7.0
Provides: bundled(golang(github.com/cloudflare/circl)) = v1.1.0
Provides: bundled(golang(github.com/containerd/cgroups)) = v1.0.3
Provides: bundled(golang(github.com/containerd/containerd)) = v1.6.8
Provides: bundled(golang(github.com/containernetworking/cni)) = v1.1.2
Provides: bundled(golang(github.com/containernetworking/plugins)) = v1.1.1
Provides: bundled(golang(github.com/containers/image/v5)) = v5.22.0
Provides: bundled(golang(github.com/containers/libtrust)) = v0.0.0_20200511145503_9c3a6c22cd9a
Provides: bundled(golang(github.com/containers/ocicrypt)) = v1.1.5
Provides: bundled(golang(github.com/containers/storage)) = v1.42.0
Provides: bundled(golang(github.com/coreos/go_iptables)) = v0.6.0
Provides: bundled(golang(github.com/coreos/go_systemd/v22)) = v22.3.2
Provides: bundled(golang(github.com/cpuguy83/go_md2man/v2)) = v2.0.2
Provides: bundled(golang(github.com/creack/pty)) = v1.1.18
Provides: bundled(golang(github.com/cyphar/filepath_securejoin)) = v0.2.3
Provides: bundled(golang(github.com/d2g/dhcp4)) = v0.0.0_20170904100407_a1d1b6c41b1c
Provides: bundled(golang(github.com/d2g/dhcp4client)) = v1.0.0
Provides: bundled(golang(github.com/docker/cli)) = v20.10.17+incompatible
Provides: bundled(golang(github.com/docker/distribution)) = v2.8.1+incompatible
Provides: bundled(golang(github.com/docker/docker)) = v20.10.17+incompatible
Provides: bundled(golang(github.com/docker/docker_credential_helpers)) = v0.6.4
Provides: bundled(golang(github.com/docker/go_connections)) = v0.4.0
Provides: bundled(golang(github.com/docker/go_metrics)) = v0.0.1
Provides: bundled(golang(github.com/docker/go_units)) = v0.4.0
Provides: bundled(golang(github.com/docker/libtrust)) = v0.0.0_20160708172513_aabc10ec26b7
Provides: bundled(golang(github.com/fatih/color)) = v1.13.0
Provides: bundled(golang(github.com/felixge/httpsnoop)) = v1.0.1
Provides: bundled(golang(github.com/fsnotify/fsnotify)) = v1.5.1
Provides: bundled(golang(github.com/garyburd/redigo)) = v0.0.0_20150301180006_535138d7bcd7
Provides: bundled(golang(github.com/ghodss/yaml)) = v1.0.0
Provides: bundled(golang(github.com/go_log/log)) = v0.2.0
Provides: bundled(golang(github.com/godbus/dbus/v5)) = v5.0.6
Provides: bundled(golang(github.com/gofrs/uuid)) = v4.0.0+incompatible
Provides: bundled(golang(github.com/gogo/protobuf)) = v1.3.2
Provides: bundled(golang(github.com/golang/groupcache)) = v0.0.0_20210331224755_41bb18bfe9da
Provides: bundled(golang(github.com/golang/protobuf)) = v1.5.2
Provides: bundled(golang(github.com/google/go_cmp)) = v0.5.8
Provides: bundled(golang(github.com/google/go_containerregistry)) = v0.10.0
Provides: bundled(golang(github.com/google/uuid)) = v1.3.0
Provides: bundled(golang(github.com/gorilla/handlers)) = v1.5.1
Provides: bundled(golang(github.com/gorilla/mux)) = v1.8.0
Provides: bundled(golang(github.com/gosimple/slug)) = v1.12.0
Provides: bundled(golang(github.com/gosimple/unidecode)) = v1.0.1
Provides: bundled(golang(github.com/hashicorp/errwrap)) = v1.1.0
Provides: bundled(golang(github.com/hashicorp/go_multierror)) = v1.1.1
Provides: bundled(golang(github.com/inconshreveable/mousetrap)) = v1.0.0
Provides: bundled(golang(github.com/json_iterator/go)) = v1.1.12
Provides: bundled(golang(github.com/kardianos/osext)) = v0.0.0_20190222173326_2bc1f35cddc0
Provides: bundled(golang(github.com/klauspost/compress)) = v1.15.9
Provides: bundled(golang(github.com/klauspost/pgzip)) = v1.2.5
Provides: bundled(golang(github.com/letsencrypt/boulder)) = v0.0.0_20220331220046_b23ab962616e
Provides: bundled(golang(github.com/mattn/go_colorable)) = v0.1.12
Provides: bundled(golang(github.com/mattn/go_isatty)) = v0.0.14
Provides: bundled(golang(github.com/mattn/go_runewidth)) = v0.0.13
Provides: bundled(golang(github.com/mattn/go_shellwords)) = v1.0.12
Provides: bundled(golang(github.com/matttproud/golang_protobuf_extensions)) = v1.0.2_0.20181231171920_c182affec369
Provides: bundled(golang(github.com/miekg/pkcs11)) = v1.1.1
Provides: bundled(golang(github.com/moby/locker)) = v1.0.1
Provides: bundled(golang(github.com/moby/sys/mount)) = v0.3.0
Provides: bundled(golang(github.com/moby/sys/mountinfo)) = v0.6.2
Provides: bundled(golang(github.com/moby/term)) = v0.0.0_20210610120745_9d4ed1856297
Provides: bundled(golang(github.com/modern_go/concurrent)) = v0.0.0_20180306012644_bacd9c7ef1dd
Provides: bundled(golang(github.com/modern_go/reflect2)) = v1.0.2
Provides: bundled(golang(github.com/morikuni/aec)) = v1.0.0
Provides: bundled(golang(github.com/networkplumbing/go_nft)) = v0.2.0
Provides: bundled(golang(github.com/opencontainers/go_digest)) = v1.0.0
Provides: bundled(golang(github.com/opencontainers/image_spec)) = v1.0.3_0.20220114050600_8b9d41f48198
Provides: bundled(golang(github.com/opencontainers/runc)) = v1.1.4
Provides: bundled(golang(github.com/opencontainers/runtime_spec)) = v1.0.3_0.20210326190908_1c3f411f0417
Provides: bundled(golang(github.com/opencontainers/runtime_tools)) = v0.9.1_0.20210326182921_59cdde06764b
Provides: bundled(golang(github.com/opencontainers/selinux)) = v1.10.1
Provides: bundled(golang(github.com/opencontainers/umoci)) = v0.4.7
Provides: bundled(golang(github.com/pelletier/go_toml)) = v1.9.5
Provides: bundled(golang(github.com/pkg/errors)) = v0.9.1
Provides: bundled(golang(github.com/proglottis/gpgme)) = v0.1.3
Provides: bundled(golang(github.com/prometheus/client_golang)) = v1.12.1
Provides: bundled(golang(github.com/prometheus/client_model)) = v0.2.0
Provides: bundled(golang(github.com/prometheus/common)) = v0.32.1
Provides: bundled(golang(github.com/prometheus/procfs)) = v0.7.3
Provides: bundled(golang(github.com/rivo/uniseg)) = v0.2.0
Provides: bundled(golang(github.com/rootless_containers/proto)) = v0.1.0
Provides: bundled(golang(github.com/russross/blackfriday/v2)) = v2.1.0
Provides: bundled(golang(github.com/safchain/ethtool)) = v0.0.0_20210803160452_9aa261dae9b1
Provides: bundled(golang(github.com/seccomp/containers_golang)) = v0.6.0
Provides: bundled(golang(github.com/seccomp/libseccomp_golang)) = v0.9.2_0.20220502022130_f33da4d89646
Provides: bundled(golang(github.com/sergi/go_diff)) = v1.2.0
Provides: bundled(golang(github.com/shopspring/decimal)) = v1.3.1
Provides: bundled(golang(github.com/sigstore/sigstore)) = v1.3.1_0.20220629021053_b95fc0d626c1
Provides: bundled(golang(github.com/sirupsen/logrus)) = v1.9.0
Provides: bundled(golang(github.com/spf13/cobra)) = v1.5.0
Provides: bundled(golang(github.com/spf13/pflag)) = v1.0.5
Provides: bundled(golang(github.com/stefanberger/go_pkcs11uri)) = v0.0.0_20201008174630_78d3cae3a980
Provides: bundled(golang(github.com/sylabs/json_resp)) = v0.8.1
Provides: bundled(golang(github.com/syndtr/gocapability)) = v0.0.0_20200815063812_42c35b437635
Provides: bundled(golang(github.com/theupdateframework/go_tuf)) = v0.3.1
Provides: bundled(golang(github.com/titanous/rocacheck)) = v0.0.0_20171023193734_afe73141d399
Provides: bundled(golang(github.com/ulikunitz/xz)) = v0.5.10
Provides: bundled(golang(github.com/urfave/cli)) = v1.22.5
Provides: bundled(golang(github.com/vbatts/go_mtree)) = v0.5.0
Provides: bundled(golang(github.com/vbatts/tar_split)) = v0.11.2
Provides: bundled(golang(github.com/vbauerster/mpb/v7)) = v7.4.2
Provides: bundled(golang(github.com/vishvananda/netlink)) = v1.1.1_0.20210330154013_f5de75959ad5
Provides: bundled(golang(github.com/vishvananda/netns)) = v0.0.0_20210104183010_2eb08e3e575f
Provides: bundled(golang(github.com/xeipuuv/gojsonpointer)) = v0.0.0_20190905194746_02993c407bfb
Provides: bundled(golang(github.com/xeipuuv/gojsonreference)) = v0.0.0_20180127040603_bd5ef7bd5415
Provides: bundled(golang(github.com/xeipuuv/gojsonschema)) = v1.2.0
Provides: bundled(golang(github.com/yvasiyarov/go_metrics)) = v0.0.0_20150112132944_c25f46c4b940
Provides: bundled(golang(github.com/yvasiyarov/gorelic)) = v0.0.6
Provides: bundled(golang(github.com/yvasiyarov/newrelic_platform_go)) = v0.0.0_20160601141957_9c099fbc30e9
Provides: bundled(golang(go.etcd.io/bbolt)) = v1.3.6
Provides: bundled(golang(go.mozilla.org/pkcs7)) = v0.0.0_20200128120323_432b2356ecb1
Provides: bundled(golang(golang.org/x/crypto)) = v0.0.0_20220525230936_793ad666bf5e
Provides: bundled(golang(golang.org/x/net)) = v0.0.0_20220624214902_1bab6f366d9e
Provides: bundled(golang(golang.org/x/sync)) = v0.0.0_20220601150217_0de741cfad7f
Provides: bundled(golang(golang.org/x/sys)) = v0.0.0_20220715151400_c0bba94af5f8
Provides: bundled(golang(golang.org/x/term)) = v0.0.0_20210927222741_03fcf44c2211
Provides: bundled(golang(golang.org/x/text)) = v0.3.7
Provides: bundled(golang(google.golang.org/genproto)) = v0.0.0_20220624142145_8cd45d7dbd1f
Provides: bundled(golang(google.golang.org/grpc)) = v1.47.0
Provides: bundled(golang(google.golang.org/protobuf)) = v1.28.0
Provides: bundled(golang(gopkg.in/square/go_jose.v2)) = v2.6.0
Provides: bundled(golang(gopkg.in/yaml.v2)) = v2.4.0
Provides: bundled(golang(gopkg.in/yaml.v3)) = v3.0.1
Provides: bundled(golang(gotest.tools/v3)) = v3.3.0
Provides: bundled(golang(mvdan.cc/sh/v3)) = v3.5.1
Provides: bundled(golang(oras.land/oras_go)) = v1.2.0
 
%if "%{_target_vendor}" == "suse"
BuildRequires: binutils-gold
%endif
BuildRequires: golang
BuildRequires: git
BuildRequires: gcc
BuildRequires: make
BuildRequires: libseccomp-devel
%if "%{_target_vendor}" == "suse"
Requires: squashfs
%else
Requires: squashfs-tools
%endif
BuildRequires: cryptsetup
%if "%{?squashfuse_version}" != ""
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool
BuildRequires: pkgconfig
BuildRequires: fuse3-devel
BuildRequires: zlib-devel
%endif
# Requires: squashfuse
Requires: fakeroot
Requires: fuse-overlayfs
Requires: e2fsprogs
# Uncomment this for the epel build, but we don't want it for the Apptainer
#  release build because there the same rpm is shared across OS versions
%if 0%{?el7}
Requires: fuse2fs
%endif
 
%description
Apptainer provides functionality to make portable
containers that can be used across host environments.
 
%package suid
Summary: Setuid component of Apptainer
Requires: %{name} = %{version}-%{release}
# The singularity package was renamed to apptainer.  The Obsoletes is
# on this subpackage for greater compatibility after an update from the
# old singularity.
Obsoletes: singularity <= %{last_singularity_version}
# FESCo asked to have this form of Provides
Provides: alternative-for(singularity)
 
%description suid
Provides the optional setuid-root portion of Apptainer.
 
%prep
%if "%{?squashfuse_version}" != ""
# the default directory for other steps is where the %%prep section ends
# so do main package last
%setup -b 10 -n squashfuse-%{squashfuse_version}
%patch -P 10 -p1
%patch -P 11 -p1
%patch -P 12 -p1
%setup -n %{name}-%{package_version}
%patch -P 0 -p1
%else
%autosetup -n %{name}-%{package_version}
%endif
 
%build
%if "%{?squashfuse_version}" != ""
pushd ../squashfuse-%{squashfuse_version}
./autogen.sh
FLAGS=-std=c99 ./configure --enable-multithreading
%make_build squashfuse_ll
popd
%endif
 
%if "%{?SOURCE1}" != ""
GOVERSION="$(echo %SOURCE1|sed 's,.*/,,;s/go//;s/\.src.*//')"
if ! ./mlocal/scripts/check-min-go-version go $GOVERSION; then
	# build the go tool chain, the existing version is too old
	pushd ..
	tar -xf %SOURCE1
	cd go/src
	./make.bash
	cd ../..
	export PATH=$PWD/go/bin:$PATH
	popd
fi
%endif
 
# Not all of these parameters currently have an effect, but they might be
#  used someday.  They are the same parameters as in the configure macro.
./mconfig %{?mconfig_opts} -V %{version}-%{release} --with-suid \
        --prefix=%{_prefix} \
        --exec-prefix=%{_exec_prefix} \
        --bindir=%{_bindir} \
        --sbindir=%{_sbindir} \
        --sysconfdir=%{_sysconfdir} \
        --datadir=%{_datadir} \
        --includedir=%{_includedir} \
        --libdir=%{_libdir} \
        --libexecdir=%{_libexecdir} \
        --localstatedir=%{_localstatedir} \
        --sharedstatedir=%{_sharedstatedir} \
        --mandir=%{_mandir} \
        --infodir=%{_infodir}
 
%make_build -C builddir V= old_config=
 
%install
%if "%{?SOURCE1}" != ""
export PATH=$PWD/go/bin:$PATH
%endif
 
%make_install -C builddir V=
%if "%{?squashfuse_version}" != ""
install -m 755 ../squashfuse-%{squashfuse_version}/squashfuse_ll %{buildroot}%{_libexecdir}/%{name}/bin/squashfuse_ll
%endif
 
%if 0%{?el7}
# Check for fuse2fs only as a pre-install so that an rpm built on el7 can
# be used on el8 & el9.  Only el7 has a fuse2fs package, the others have 
# the fuse2fs program in the e2fsprogs package.
%pre
if [ ! -f /usr/bin/fuse2fs ] && [ ! -f /usr/sbin/fuse2fs ]; then
	echo "fuse2fs not found, please yum install /usr/*bin/fuse2fs from epel" >&2
	exit 1
fi
%endif
 
%post
# $1 in %%posttrans cannot distinguish between fresh installs and upgrades,
# so check it here and create a file to pass the knowledge to that step
if [ "$1" -eq 1 ] && [ -d %{_sysconfdir}/singularity ]; then
	touch %{_sysconfdir}/%{name}/.singularityupgrade
fi
 
%posttrans
# clean out empty directories under /etc/singularity
rmdir %{_sysconfdir}/singularity/* %{_sysconfdir}/singularity 2>/dev/null || true
if [ -f %{_sysconfdir}/%{name}/.singularityupgrade ]; then
	pushd %{_sysconfdir}/%{name} >/dev/null
	rm .singularityupgrade
	# This is the first install of apptainer after removal of singularity.
	# Import any singularity configurations that remain, which were left
	# because they were non-default.
	find %{_sysconfdir}/singularity ! -type d 2>/dev/null|while read F; do
		B="$(echo $F|sed 's,%{_sysconfdir}/singularity/,,;s/\.rpmsave//')"
		if [ "$B" == singularity.conf ]; then
			echo "info: renaming $PWD/%{name}.conf to $PWD/%{name}.conf.rpmorig" >&2
			mv %{name}.conf %{name}.conf.rpmorig
			echo "info: converting configuration from $F into $PWD/%{name}.conf" >&2
			%{_bindir}/%{name} confgen $F %{name}.conf
		elif [ "$B" == remote.yaml ]; then
			echo "info: renaming $PWD/$B to $PWD/$B.rpmorig" >&2
			mv $B $B.rpmorig
			echo "info: merging $F into $PWD/$B" >&2
			(
			sed -n '1p' $F
			sed -n '2,$p' $B.rpmorig
			sed -n '3,$p' $F
			) >$B
		else
			if [ -f "$B" ]; then
				echo "info: renaming $PWD/$B to $PWD/$B.rpmorig" >&2
				mv $B $B.rpmorig
			fi
			echo "info: copying $F into $PWD/$B" >&2
			cp $F $B
		fi
	done
	popd >/dev/null
fi
 
# Define `%%license` tag if not already defined.
# This is needed for EL 7 compatibility.
%{!?_licensedir:%global license %doc}
 
%files
%{_bindir}/%{name}
%{_bindir}/singularity
%{_bindir}/run-singularity
%dir %{_libexecdir}/%{name}
%dir %{_libexecdir}/%{name}/bin
%{_libexecdir}/%{name}/bin/starter
%if "%{?squashfuse_version}" != ""
%{_libexecdir}/%{name}/bin/squashfuse_ll
%endif
%{_libexecdir}/%{name}/cni
%{_libexecdir}/%{name}/lib
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/*
%{_datadir}/bash-completion/completions/*
%dir %{_localstatedir}/%{name}
%dir %{_localstatedir}/%{name}/mnt
%dir %{_localstatedir}/%{name}/mnt/session
%{_mandir}/man1/%{name}*
%{_mandir}/man1/singularity*
%license LICENSE.md
%license LICENSE_THIRD_PARTY.md
%license LICENSE_DEPENDENCIES.md
%doc README.md
%doc CHANGELOG.md
 
%files suid
%attr(4755, root, root) %{_libexecdir}/%{name}/bin/starter-suid
 
%changelog
* Tue Feb 21 2023 Yikun<yikunkero@gmail.com> - 1.1.6-1
- Init package

