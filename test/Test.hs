{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}

import Test.Tasty
import Common
import Prelude hiding (maximum)
import CSE.Password
import qualified Data.Map as M 


-- unit test generate
prop_generate_cap :: Int -> IO Bool
prop_generate_cap 0 = return True
prop_generate_cap n = do pass <- passWordGeneration
                         case (isUpper (pass !! 0)) of
                            True -> prop_generate_cap (n-1)
                            _    -> return False

prop_generate_len 0 = return True
prop_generate_len n = do pass <- passWordGeneration
                         case ((length pass) >= 8) && ((length pass) <= 16) of
                            True -> prop_generate_len (n-1)
                            _    -> return False

prop_generate_diff 0 = return True
prop_generate_diff n = do pass1 <- passWordGeneration
                          pass2 <- passWordGeneration
                          case (pass1 /= pass2) of
                            True -> prop_generate_diff (n-1)
                            _    -> return False


storeLocal "Amazon" "Jesse"
storeLocal "Google" "Jax"
storeLocal "Youtube" "Jesscia"
storeLocal "Twitch" "Max"
storeLocal "Bestbuy" "Julian"

store_local_jesse = do 
    contents <- IS.readFile "src/file.txt"
    k <- getStdRandom (randomR(1, 500)) :: IO Int   
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    let passencry = encryptHelper k pass
    let replaced = replacePassWord web user k passencry res
