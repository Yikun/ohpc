#-------------------------------------------------------------------------------
# Copyright (c) 2015, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#-------------------------------------------------------------------------------

# MVAPICH2 MPI stack that is dependent on compiler toolchain

%define with_slurm 1

#-fsp-header-comp-begin----------------------------------------------

# FSP convention: the default assumes the gnu compiler family;
# however, this can be overridden by specifing the compiler_family
# variable via rpmbuild or other mechanisms.

%{!?compiler_family: %define compiler_family gnu}
%{!?PROJ_DELIM:      %define PROJ_DELIM   %{nil}}

# Compiler dependencies
BuildRequires: lmod%{PROJ_DELIM}
%if %{compiler_family} == gnu
BuildRequires: gnu-compilers%{PROJ_DELIM}
Requires:      gnu-compilers%{PROJ_DELIM}
%endif
%if %{compiler_family} == intel
BuildRequires: gcc-c++ intel-compilers-devel%{PROJ_DELIM}
Requires:      gcc-c++ intel-compilers-devel%{PROJ_DELIM}
%if 0%{FSP_BUILD}
BuildRequires: intel_licenses
%endif
%endif

#-fsp-header-comp-end------------------------------------------------

%if 0%{with_slurm}
BuildRequires: slurm-devel%{PROJ_DELIM} slurm%{PROJ_DELIM}
%endif

# Base package name
%define pname mvapich2

Summary:   OSU MVAPICH2 MPI implementation
Name:      %{pname}-%{compiler_family}%{PROJ_DELIM}
Version:   2.1
Release:   1
License:   BSD
Group:     fsp/mpi-families
URL:       http://mvapich.cse.ohio-state.edu/overview/mvapich2/
Source0:   %{pname}-%{version}.tar.gz
Source1:   FSP_macros
Source2:   FSP_setup_compiler
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%include %{_sourcedir}/FSP_macros

%define debug_package %{nil}

%if 0%{?sles_version} || 0%{?suse_version}
Buildrequires: ofed 
%endif
%if 0%{?rhel_version} || 0%{?centos_version}
Buildrequires: rdma
%endif

BuildRequires: bison
BuildRequires: libibmad-devel libibverbs-devel

# Default library install path
%define install_path %{FSP_MPI_STACKS}/%{name}/%version

%description 

MVAPICH2 is a high performance MPI-2 implementation (with initial
support for MPI-3) for InfiniBand, 10GigE/iWARP and RoCE.  MVAPICH2
provides underlying support for several interfaces (such as OFA-IB,
OFA-iWARP, OFA-RoCE, PSM, Shared Memory, and TCP) for portability
across multiple networks.

%prep

%setup -q -n %{pname}-%{version}

%build

# FSP compiler designation
export FSP_COMPILER_FAMILY=%{compiler_family}
. %{_sourcedir}/FSP_setup_compiler

./configure --prefix=%{install_path} \
	    --enable-cxx \
	    --enable-g=dbg \
%if 0%{with_slurm}
            --with-pm=no --with-pmi=slurm \
%endif
	    --enable-fast=O3 || cat config.log

%install

# FSP compiler designation
export FSP_COMPILER_FAMILY=%{compiler_family}
. %{_sourcedir}/FSP_setup_compiler

#make %{?_smp_mflags} DESTDIR=$RPM_BUILD_ROOT install

# 06/04/15 - karl.w.schulz@intel.com; running build twice to deal with module dependency
make %{?_smp_mflags} 
make %{?_smp_mflags} DESTDIR=$RPM_BUILD_ROOT install

# Remove .la files detected by rpm

rm $RPM_BUILD_ROOT/%{install_path}/lib/*.la


# FSP module file
%{__mkdir} -p %{buildroot}/%{FSP_MODULEDEPS}/%{compiler_family}/%{pname}
%{__cat} << EOF > %{buildroot}/%{FSP_MODULEDEPS}/%{compiler_family}/%{pname}/%{version}
#%Module1.0#####################################################################

proc ModulesHelp { } {

puts stderr " "
puts stderr "This module loads the %{pname} library built with the %{compiler_family} toolchain."
puts stderr "\nVersion %{version}\n"

}
module-whatis "Name: %{pname} built with %{compiler_family} toolchain"
module-whatis "Version: %{version}"
module-whatis "Category: runtime library"
module-whatis "Description: %{summary}"
module-whatis "URL: %{url}"

set     version			    %{version}

prepend-path    PATH                %{install_path}/bin
prepend-path    MANPATH             %{install_path}/man
prepend-path	LD_LIBRARY_PATH	    %{install_path}/lib
prepend-path    MODULEPATH          %{FSP_MODULEDEPS}/%{compiler_family}-%{pname}
prepend-path    MPI_DIR             %{install_path}
prepend-path    PKG_CONFIG_PATH     %{install_path}/lib/pkgconfig

family "MPI"
EOF

%{__cat} << EOF > %{buildroot}/%{FSP_MODULEDEPS}/%{compiler_family}/%{pname}/.version.%{version}
#%Module1.0#####################################################################
##
## version file for %{pname}-%{version}
##
set     ModulesVersion      "%{version}"
EOF

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig || exit 1

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{FSP_HOME}


%changelog
* Tue Aug  5 2014  <karl.w.schulz@intel.com> - 
- Initial build.

