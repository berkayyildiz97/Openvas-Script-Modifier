###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server Remote Code Execution vulnerability (2834052)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903322");
  script_version("2020-01-07T09:06:32+0000");
  script_cve_id("CVE-2013-1330", "CVE-2013-3179", "CVE-2013-3180", "CVE-2013-0081");
  script_bugtraq_id(62221, 62227, 62254, 62205);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-09-13 16:29:08 +0530 (Fri, 13 Sep 2013)");
  script_name("Microsoft SharePoint Server Remote Code Execution vulnerability (2834052)");


  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
Bulletin MS13-067.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"Multiple Flaws are due to,

  - An error when handling an unassigned workflow can be exploited to cause the
  W3WP process to stop responding via a specially crafted URL.

  - An error related to MAC exists when handling unassigned workflows.

  - Input passed via the 'ms-descriptionText > ctl00_PlaceHolderDialogBodySection
  _PlaceHolderDialogBodyMainSection_ValSummary' parameter related to metadata
  storage assignment of the BDC permission management within the 'Sharepoint
  Online Cloud 2013 Service' section is not properly sanitised before being used.

  - Certain unspecified input is not properly sanitised before being returned to
   the user.

  - Multiple unspecified errors.");
  script_tag(name:"affected", value:"- Microsoft SharePoint Server 2013

  - Microsoft SharePoint Server 2007 Service Pack 3

  - Microsoft SharePoint Server 2010 Service Pack 2 and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct script insertion
attacks, cause a DoS (Denial of Service), and compromise a vulnerable system.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=812");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-067");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-067");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

shareVer = get_app_version(cpe:CPE);
if(!shareVer){
  exit(0);
}

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## SharePoint Server 2010 (wosrv & coreserver)
if(shareVer =~ "^14\..*")
{
  path = registry_get_sz(key: key + "14.0", item:"Location");

  dllVer = fetch_file_version(sysPath:path, file_name:"ISAPI\Microsoft.office.server.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7010.999"))
    {
      if(!port = get_app_port(cpe: CPE)) port = 0;
      security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
      exit(0);
    }
  }
}

## SharePoint Server 2013 (coreserverloc)
if(shareVer =~ "^15\..*")
{
  path = registry_get_sz(key: key + "15.0", item:"Location");

  dllVer = fetch_file_version(sysPath:path, file_name:"ISAPI\Microsoft.office.server.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4525.999"))
    {
      if(!port = get_app_port(cpe: CPE)) port = 0;
      security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
      exit(0);
    }
  }
}
