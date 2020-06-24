$(document).ready(function(){
    $("#status_code").change(function(){
        if($(this).val() === "plus"){
             $(".value200").show();
             $(".value403").hide();
             $(".value401").hide();
             $(".value400").hide();
             $(".value300").hide();
         }
         else if($(this).val() === "redirect"){
             $(".value300").show();
             $(".value200").hide();
             $(".value403").hide();
             $(".value401").hide();
             $(".value400").hide(); 
         }
         else if($(this).val() === "forbi"){
             $(".value403").show();
             $(".value401").show();
             $(".value400").show();
             $(".value200").hide();
             $(".value300").hide();
         }
         else{
             $(".value200").show();
             $(".value403").show();
         }
    });
});


