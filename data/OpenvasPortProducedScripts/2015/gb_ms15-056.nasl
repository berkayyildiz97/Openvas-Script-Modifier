###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Memory Corruption Vulnerabilities (3058515)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805196");
  script_version("2019-12-20T10:24:46+0000");
  script_cve_id("CVE-2015-1687", "CVE-2015-1730", "CVE-2015-1731", "CVE-2015-1732",
                "CVE-2015-1735", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739",
                "CVE-2015-1740", "CVE-2015-1741", "CVE-2015-1742", "CVE-2015-1743",
                "CVE-2015-1744", "CVE-2015-1745", "CVE-2015-1747", "CVE-2015-1748",
                "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1752", "CVE-2015-1753",
                "CVE-2015-1754", "CVE-2015-1755", "CVE-2015-1765", "CVE-2015-1766");
  script_bugtraq_id(74974, 74982, 74985, 74986, 74988, 74990, 74991);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2015-06-10 08:08:31 +0530 (Wed, 10 Jun 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Memory Corruption Vulnerabilities (3058515)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-056.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper
  handling memory objects when accessing it and does not properly validate
  permissions under specific conditions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to corrupt memory and potentially execute arbitrary code in the
  context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Internet Explorer version
  6.x/7.x/8.x/9.x/10.x/11.x");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3058515");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-056");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^([6-9|1[01])\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5624") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21465")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23686")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19382")||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23689")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19631")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23686")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16658")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20773")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.17000", test_version2:"8.0.7601.18869")||
     version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.23072")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16658")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20773")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17376")||
     version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21488")||
     version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.17841")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17376")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21488")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.9600.17842")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

exit(99);
