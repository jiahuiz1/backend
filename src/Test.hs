module CSE230.Unittest where

import System.Random
import System.Random.Stateful
import Data.Aeson
import qualified Data.Text as T
import qualified Data.ByteString.Lazy.Internal as B
import qualified Data.ByteString.Char8 as BS
import GHC.Generics
import Control.Monad (replicateM)
import Data.String
import Prelude as P
import Foreign.C (CSChar(CSChar))
import Data.Char
import Data.List.Split as S
import Text.Read (Lexeme(Char))
import qualified Data.Map as M
import Control.Monad.State
import Control.Applicative (Alternative(empty))
import Data.List.NonEmpty (some1)
import Control.Monad.Identity (Identity (Identity, Identity))
import Data.IntMap (findWithDefault)
import Data.ByteString (ByteString, putStrLn)
import Data.Tuple.Select
import System.IO.Strict as IS
import System.Directory
import CSE230.Password

-- unit test generate
-- for testing

run_test1 = do
    c1 <- prop_generate_cap 100
    c2 <- prop_generate_len 100
    c3 <- prop_generate_diff 100
    _ <- store_local
    s1 <- test_for_store0 "Google" "Jesse"
    s2 <- test_for_store0 "Amazon" "Jack"
    s3 <- test_for_store0 "Twitch" "Michal"
    s4 <- test_for_store0 "Amazon" "Jesscia"
    s5 <- test_for_store0 "Youtube" "Julian"
    s6 <- test_for_store0 "Youtube" "Jeffery" 

    s7 <- test_for_search_user "Jes"
    s8 <- test_for_search_user "Juli"
    s9 <- test_for_search_user "Jack"
    s10 <- test_for_search_user "Je"
    s11 <- test_for_search_web "Ama"
    s12 <- test_for_search_web "Google"
    -- return ((c1, "password generation checked 100 times"), (c2, "password generation checked 100 times"), (c3, "password generation checked 100 times"), (s1, "store check for Jesse"),  (s2, "store check for Jack"),  (s3, "store check for Michal"),
    --  (s4, "store check for Jesscia"), (s5, "store check for Julian"), (s6, "store check for Jeffery"), (s6, "search check for Jes"), (s6, "search check for Juli"), (s6, "search check for Jack")
    --  ,(s6, "search check for Jes"), (s6, "search check for Jes"), (s6, "search check for Jes"), (s6, "search check for Jes"), (d1, "delete check for Jesse"), (d2, "delete check for Julian"), (d3, "delete check for Jack"))
    return ((c1, "password generation checked"), (c2, "password generation checked"), (c3, "password generation checked"), (s1, "store check for Jesse"),  (s2, "store check for Jack"),  (s3, "store check for Michal"), (s4, "store check for Jesscia"), (s5, "store check for Julian"), (s6, "store check for Jeffery"), (s7, "search check for Jes"), (s8, "search check for Juli"), (s9, "search check for Jes"), (s10, "search check for Je"), (s11, "search check for Ama"), (s12, "search check for Google"))


run_test2 = do
    s13 <- test_for_search_web "Twit"
    s14 <- test_for_search_web "Yout"

    d1 <- test_for_delete "Google" "Jesse"
    d2 <- test_for_delete "Youtube" "Julian"
    d3 <- test_for_delete "Amazon" "Jack"
    return ((s13, "search check for Twit"), (s14, "search check for Yout"), (d1, "delete check for Jesse"), (d2, "delete check for Jesse"), (d3, "delete check for Jesse"))

-- for password
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


store_local = do
    t1 <- storeLocal "Google" "Jesse"
    t2 <- storeLocal "Amazon" "Jack"
    t3 <- storeLocal "Twitch" "Michal"
    t4 <- storeLocal "Amazon" "Jesscia"
    t5 <- storeLocal "Youtube" "Julian"
    t6 <- storeLocal "Youtube" "Jeffery"
    return ()


teststore0 = storeLocal "Google" "Jesse"
teststore1 = storeLocal "Amazon" "Jack"
teststore2 = storeLocal "Twitch" "Michal"
teststore3 = storeLocal "Youtube" "Julian"
teststore4 = storeLocal "Amazon" "Jesscia"
teststore5 = storeLocal "Youtube" "Julian"
teststore6 = storeLocal "Youtube" "Jeffery"

check_web_user:: String -> String -> [PassWordInfo] -> IO Bool
check_web_user web user []     = return False
check_web_user web user (x:xs) = if (website x) == web && (userName x) == user
                                    then return True
                                    else check_web_user web user xs

test_for_store0 :: String -> String -> IO Bool
test_for_store0 w u = do
    contents <- IS.readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    final <- check_web_user w u res
    return final


search_check_user ::String -> [(String, String, PassWord)] -> IO Bool
search_check_user  u []    = return False
search_check_user  u ((s1, s2, p):xs) = if (T.isInfixOf (T.pack u) (T.pack s2))
                                    then return True
                                    else search_check_user u xs

search_check_web ::String -> [(String, String, PassWord)] -> IO Bool
search_check_web  u []    = return False
search_check_web  u ((s1, s2, p):xs) = if (T.isInfixOf (T.pack u) (T.pack s1))
                                    then return True
                                    else search_check_user u xs

test_for_search_user :: String -> IO Bool
test_for_search_user u = do
    contents <- IS.readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    let check = searchHelper u res
    final <- search_check_user u check
    return (final)

test_for_search_web :: String -> IO Bool
test_for_search_web w = do
    contents <- IS.readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    let check = searchHelper w res
    final <- search_check_web w check
    return (final)

delete_check :: String -> String -> [(String, String, PassWord)] -> IO Bool
delete_check w u []    = return True
delete_check w u ((s1, s2, p):xs)= if s1 == w && s2 == w
                                    then return False
                                    else delete_check w u xs

test_for_delete :: String -> String -> IO Bool
test_for_delete web user  = do
    deleted <- deletePassWord web user
    res <- (delete_check web user deleted)
    return res