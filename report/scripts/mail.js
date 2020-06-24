$(document).ready(function(){    
    $("#mail_pnwd").change(function(){
        if($(this).val() === "pwnd"){
            // Show input field
            $(".pwned").show();
            $(".no_pwned").show();
        }
        else if($(this).val() === "npwnd"){
            $(".pwned").show();
            $(".no_pwned").show(); 
        }
        else{
            $(".pwned").show();
            $(".no_pwned").show();
        }
    });
});