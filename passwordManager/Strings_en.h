//
// Created by zutt on 4/22/19.
//

#define WELCOME "\n##############################################################################\n#\n# Welcome to my new password manager\n#\n##############################################################################\n\n"

// *****************************************************************************************************************
// * 1. AUTHENTIFICATION [LOCK]
// *****************************************************************************************************************

#define BAD_AUTHENTIFICATION "SERIOUS YOU DON'T REMEMBER THE PASSWORD !!!! BYE !\n"
#define NUMBER_AUTH_PART1 "type you password, you have "
#define NUMBER_AUTH_PART2 " chance before the explosion of this program\n"

// *****************************************************************************************************************
// * 2. DERIVING MASTER KEY, DECRYPT GENEREAL KEY [UNLOCK]
// *****************************************************************************************************************

#define EROOR_DERIVING_MASTERKEY "Error during deriviation MasterKey from Master Password\n"
#define EROOR_DECRYPT_GENERALKEY "Error during decryption of General Key \n"

// *****************************************************************************************************************
// * 3. ASK FOR ACTION [UNLOCK]
// *****************************************************************************************************************

#define MENU "List of Actions (type number for choice) : \n 1. Add new password \n 2. Get a password \n 3. Modify Master Password \n 4. Lock the programme \n"
#define MENU_ENTRY_NOT_VALID "Sorry, the action number is not valid\n"

// *****************************************************************************************************************
// * ADDING NEW PASSWORD TO FILE
// *****************************************************************************************************************
#define ADDING_PASSWORD_URL "\nType the URL corresponding to the password : \n"
#define ADDING_PASSWORD_PASSWORD "\nType the password corresponding to the url : \n"
#define ADDING_PASSWORD_ERROR "Error during encryption of password \n"
#define ADDING_PASSWORD_MAX_LENGTH_INPUT "Max length : "
#define ADDING_PASSWORD_MAX_LENGTH_INPUT_NUMBER 128
#define ADDING_PASSWORD_NONCE "_NONCE"
#define ADDING_PASSWORD_LENGTH "_LENGTH"

// *****************************************************************************************************************
// * GET PASSWORD FROM FILE
// *****************************************************************************************************************
#define GET_PASSWORD_URL "\nType the URL corresponding to the password : \n"
#define GET_PASSWORD_ERROR_GETURL "this url don't exist in the file \n"
#define GET_PASSWORD_ERROR_DECRYPTION "Error during decryption of password \n"
#define GET_PASSWORD_PASSWORD "Your password is : "

// *****************************************************************************************************************
// * Change Master Password
// *****************************************************************************************************************
#define ChangePass_NewPass1 "Type your new Password : \n"
#define ChangePass_NewPass2 "Type your new Password a second time to confirm : \n"
#define ChangePass_limitation "Your new password should be between 10 and 50 character, should contain at least one Majuscule and one Number\n"
#define ChangePass_OldPass "Type your old password : \n"
#define ChangePass_NotSame "These two password are not the same, try again.\n"
#define ChangePass_NotConform "password not conforme to the specifications."

// *****************************************************************************************************************
// * Lock
// *****************************************************************************************************************
#define Lock_exit "would you want to exit the programme type yes or no ? "
