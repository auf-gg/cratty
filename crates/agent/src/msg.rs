pub const FAILURE: u8 = 5;
pub const SUCCESS: u8 = 6;
pub const IDENTITIES_ANSWER: u8 = 12;
pub const SIGN_RESPONSE: u8 = 14;
pub const EXTENSION_FAILURE: u8 = 28;

pub const REQUEST_IDENTITIES: u8 = 11;
pub const SIGN_REQUEST: u8 = 13;
pub const ADD_IDENTITY: u8 = 17;
pub const REMOVE_IDENTITY: u8 = 18;
pub const REMOVE_ALL_IDENTITIES: u8 = 19;
pub const ADD_SMARTCARD_KEY: u8 = 20;
pub const REMOVE_SMARTCARD_KEY: u8 = 21;
pub const LOCK: u8 = 22;
pub const UNLOCK: u8 = 23;
pub const ADD_ID_CONSTRAINED: u8 = 25;
pub const ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub const EXTENSION: u8 = 27;

pub fn describe(kind: u8) -> &'static str {
    match kind {
        ADD_IDENTITY | ADD_ID_CONSTRAINED => {
            "добавление ключа: ключи берутся из хранилища, а не из ssh-add"
        }
        REMOVE_IDENTITY | REMOVE_ALL_IDENTITIES => {
            "удаление ключа: список ключей меняется в хранилище, а не через агента"
        }
        ADD_SMARTCARD_KEY | REMOVE_SMARTCARD_KEY | ADD_SMARTCARD_KEY_CONSTRAINED => {
            "смарт-карта: не поддерживается"
        }
        LOCK | UNLOCK => "блокировка агента: замок один — замок хранилища, второго не заводим",
        _ => "неизвестный запрос",
    }
}
