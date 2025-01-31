# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815648");
  script_version("2019-10-25T10:01:14+0000");
  script_cve_id("CVE-2019-3002", "CVE-2019-3031", "CVE-2019-1547", "CVE-2019-3021",
                "CVE-2019-2984", "CVE-2019-2944", "CVE-2019-3026", "CVE-2019-3028",
                "CVE-2019-2926", "CVE-2019-3017", "CVE-2019-3005");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-10-25 10:01:14 +0000 (Fri, 25 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-16 12:29:56 +0530 (Wed, 16 Oct 2019)");
  script_name("Oracle VirtualBox Security Updates (oct2019-5072832) 03-MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple errors
  in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.2.34 and
  6.x prior to 6.0.10 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version 5.2.34
  or 6.0.14 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html");
  script_xref(name:"URL", value:"https://www.virtualbox.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
virtualVer = infos['version'];
path = infos['location'];


if(virtualVer =~ "^6\." && version_is_less(version:virtualVer, test_version:"6.0.14")){
  fix = "6.0.14";
} else if (version_is_less(version:virtualVer, test_version:"5.2.34")){
  fix = "5.2.34";
}

if(fix)
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:fix);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(0);
