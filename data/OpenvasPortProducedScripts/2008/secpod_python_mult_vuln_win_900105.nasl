# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900105");
  script_version("2019-11-12T13:34:01+0000");
  script_bugtraq_id(30491);
  script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");
  script_tag(name:"last_modification", value:"2019-11-12 13:34:01 +0000 (Tue, 12 Nov 2019)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_copyright("Copyright (C) 2008 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_name("Python <= 2.5.2 Multiple Vulnerabilities (Windows)");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python/win/detected");

  script_xref(name:"URL", value:"http://bugs.python.org/issue2588");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2589");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2620");

  script_tag(name:"summary", value:"The host is installed with Python and is prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"The flaws exist due to multiple integer overflows in:

  - hashlib module, which can lead to an unreliable cryptographic digest
  results.

  - the processing of unicode strings.

  - the PyOS_vsnprintf() function on architectures that do not have a
  vsnprintf() function.

  - the PyOS_vsnprintf() function when passing zero-length strings can
  lead to memory corruption.");

  script_tag(name:"affected", value:"Python 2.5.2 and prior on Windows (All).");

  script_tag(name:"solution", value:"A fix is available, please see the references for more information.");

  script_tag(name:"impact", value:"Successful exploitation would allow attackers to
  execute arbitrary code or create a denial of service condition.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"2.5.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
}

exit( 99 );
