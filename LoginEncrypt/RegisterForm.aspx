<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="RegisterForm.aspx.cs" Inherits="LoginEncrypt.RegisterForm" %>

<!DOCTYPE html>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">  
    <link href="Content/bootstrap.min.css" rel="stylesheet" />  
    <script src="scripts/jquery-3.3.1.min.js"></script>  
    <script src="scripts/bootstrap.min.js"></script> 
 <style>  
        .bottom {  
            margin-bottom: 5px !important;  
        }  
    </style>  
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>  
    <form id="form1" runat="server">  
        <div class="container py-4">  
            <div class="col-md-5 offset-md-3">  
                <div class="card card-outline-secondary rounded-0">  
                    <div class="card-header bg-success rounded-0">  
                        <h4 class="text-center text-uppercase text-white">Registration</h4>  
                    </div>  
                    <div class="card-body">  
                        <div class="form-group bottom">  
                            <label>Name</label>  
                            <div class="input-group">  
                                <div class="input-group-prepend">  
                                    <div class="input-group-text"><i class="fa fa-user"></i></div>  
                                </div>  
                                <asp:TextBox ID="txtName" runat="server" CssClass="form-control"></asp:TextBox>  
                            </div>  
                            <asp:RequiredFieldValidator ID="rfvName" ControlToValidate="txtName" CssClass="text-danger" runat="server" ErrorMessage="Please enter name"></asp:RequiredFieldValidator>  
                        </div>  
                        <div class="form-group bottom">  
                            <label>Email</label>  
                            <div class="input-group">  
                                <div class="input-group-prepend">  
                                    <div class="input-group-text"><i class="fa fa-envelope"></i></div>  
                                </div>  
                                <asp:TextBox ID="txtEmail" runat="server" CssClass="form-control"></asp:TextBox>  
                            </div>  
                            <asp:RequiredFieldValidator ID="rfvEmail" Display="Dynamic" ControlToValidate="txtEmail" CssClass="text-danger" runat="server" ErrorMessage="Please enter email address"></asp:RequiredFieldValidator>  
                            <asp:RegularExpressionValidator ID="revEmail" ControlToValidate="txtEmail" CssClass="text-danger" runat="server" ErrorMessage="Enter valid email" ValidationExpression="\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*"></asp:RegularExpressionValidator>  
                        </div>  
                        <div class="form-group bottom">  
                            <label>Phone Number</label>  
                            <div class="input-group">  
                                <div class="input-group-prepend">  
                                    <div class="input-group-text"><i class="fa fa-phone"></i></div>  
                                </div>  
                                <asp:TextBox ID="txtPhoneNumber" runat="server" CssClass="form-control"></asp:TextBox>  
                            </div>  
                            <asp:RequiredFieldValidator ID="rfvPhoneNumber" Display="Dynamic" ControlToValidate="txtPhoneNumber" CssClass="text-danger" runat="server" ErrorMessage="Please enter phone number"></asp:RequiredFieldValidator>  
                            <asp:RegularExpressionValidator ID="revPhoneNumber" ControlToValidate="txtPhoneNumber" CssClass="text-danger" runat="server" ErrorMessage="Enter valid phone number" ValidationExpression="[0-9]{10}"></asp:RegularExpressionValidator>  
                        </div>  
                        <div class="form-group bottom">  
                            <label>Password</label>  
                            <div class="input-group">  
                                <div class="input-group-prepend">  
                                    <div class="input-group-text"><i class="fa fa-lock"></i></div>  
                                </div>  
                                <asp:TextBox ID="txtPassword" TextMode="Password" runat="server" CssClass="form-control"></asp:TextBox>  
                            </div>  
                            <asp:RequiredFieldValidator ID="rfvPassword" ControlToValidate="txtPassword" CssClass="text-danger" runat="server" ErrorMessage="Please enter password"></asp:RequiredFieldValidator>  
                        </div>  
                        <div class="form-group bottom">  
                            <label>Confirm Password</label>  
                            <div class="input-group">  
                                <div class="input-group-prepend">  
                                    <div class="input-group-text"><i class="fa fa-lock"></i></div>  
                                </div>  
                                <asp:TextBox ID="txtConfirmPassword" TextMode="Password" runat="server" CssClass="form-control"></asp:TextBox>  
                            </div>  
                            <asp:CompareValidator ID="CompareValidator1" ControlToCompare="txtPassword" Display="Dynamic" ControlToValidate="txtConfirmPassword" CssClass="text-danger" runat="server" ErrorMessage="Password does not match"></asp:CompareValidator>  
                            <asp:RequiredFieldValidator ID="rfvConfirmPassword" ControlToValidate="txtConfirmPassword" CssClass="text-danger" runat="server" ErrorMessage="Please enter password"></asp:RequiredFieldValidator>  
                        </div>  
                        <div class="form-group">  
                            <asp:Button ID="btnRegiter" CssClass="btn btn-success rounded-0 btn-block" runat="server" Text="Register" OnClick="btnRegiter_Click" />  
                        </div>  
                        <asp:Label ID="lblMessage" runat="server"></asp:Label>  
                    </div>  
                </div>  
            </div>  
        </div>  
    </form>  
</body>  
</html>
