###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_itma_priv_escalation_vuln_lin.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# IBM DB2 Tivoli Monitoring Agent Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802735");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1796");
  script_bugtraq_id(52326);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-06 16:59:20 +0530 (Fri, 06 Apr 2012)");
  script_name("IBM DB2 Tivoli Monitoring Agent Privilege Escalation Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48279/");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21586193");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC79970");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("secpod_ibm_db2_detect_linux_900217.nasl");
  script_mandatory_keys("Linux/IBM_db2/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow local users to perform certain actions
  with escalated privileges and gain sensitive information.");
  script_tag(name:"affected", value:"IBM DB2 version 9.5 through FP8");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error in Tivoli Monitoring Agent.");
  script_tag(name:"solution", value:"Upgrade to IBM DB2 version 9.5 FP9 or later.");
  script_tag(name:"summary", value:"This host is installed with IBM DB2 and is prone to privilege
  escalation vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21588098");
  exit(0);
}

include("version_func.inc");

ibmVer = get_kb_item("Linux/IBM_db2/Ver");
if(ibmVer == NULL){
  exit(0);
}

if(version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.0.8")){
  report = report_fixed_ver(installed_version:ibmVer, vulnerable_range:"9.5 - 9.5.0.8");
  security_message(port: 0, data: report);
}
