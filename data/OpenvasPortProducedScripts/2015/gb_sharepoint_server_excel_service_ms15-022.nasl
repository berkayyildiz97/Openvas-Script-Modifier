###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server Excel Services RCE Vulnerability (3038999)
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805148");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-0085");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-03-11 13:06:24 +0530 (Wed, 11 Mar 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SharePoint Server Excel Services RCE Vulnerability (3038999)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-022.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an use-after-free error
  that is triggered when handling a specially crafted office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to dereference already freed memory and potentially execute
  arbitrary code.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2013
  Service Pack 1 Excel Services");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2956143");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-022");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Server 2013
if(shareVer =~ "^15\..*")
{
  path = path + "\15.0\MUI\en-us";

  dllVer = fetch_file_version(sysPath:path, file_name:"ACEWSTR.DLL");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4695.999"))
    {
      if(!port = get_app_port(cpe: CPE)) port = 0;
      security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
      exit(0);
    }
  }
}

exit(99);
