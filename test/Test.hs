{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}

import Test.Tasty
import Common
import Prelude hiding (maximum)
import CSE230.Types 
import CSE230.Parse (parseFile)
import CSE230.Eval
import qualified Data.Map as M 

main :: IO ()
main = runTests 
  [ probEval
  , probParse
  ]

probEval ::  Score -> TestTree
probEval sc = testGroup "Problem 2: Eval"
  [ scoreTest ((\_ -> eval store0 (Var "Z")), (),  IntVal 0                         , 2, "eval-1")
  , scoreTest ((\_ -> eval store0 (Val  (IntVal 92))), (),  IntVal 92               , 2, "eval-2")
  , scoreTest ((\_ -> eval store0 (Op Plus  (Var "X") (Var "Y"))),  (), IntVal 30   , 2, "eval-3")
  , scoreTest ((\_ -> eval store0 (Op Minus (Var "X") (Var "Y"))),  (), IntVal (-10), 2, "eval-4")
  , scoreTest ((\_ -> eval store0 (Op Times (Var "X") (Var "Y"))),  (), IntVal 200  , 2, "eval-5")
  , scoreTest ((\_ -> eval store0 (Op Divide (Var "Y") (Var "X"))), (), IntVal 2    , 2, "eval-6")
  , scoreTest ((\_ -> eval store0 (Op Gt (Var "Y") (Var "X")))    , (), BoolVal True, 2, "eval-7")
  , scoreTest ((\_ -> eval store0 (Op Ge (Var "Y") (Var "X")))    , (), BoolVal True, 2, "eval-8")
  , scoreTest ((\_ -> eval store0 (Op Lt (Var "Y") (Var "X")))    , (), BoolVal False, 2, "eval-9")  
  , scoreTest ((\_ -> eval store0 (Op Le (Var "Y") (Var "X")))    , (), BoolVal False, 2, "eval 10") 

  , scoreTest ((\_ -> execS w_test  M.empty), (), M.fromList [("X",IntVal 0),("Y",IntVal 10)],                              5, "exec-1") 
  , scoreTest ((\_ -> execS w_fact  M.empty), (), M.fromList [("F",IntVal 2),("N",IntVal 0),("X",IntVal 1),("Z",IntVal 2)], 5, "exec-2")
  , scoreTest ((\_ -> execS w_abs   M.empty), (), M.fromList [("X",IntVal 3)]                                             , 5, "exec-3")
  , scoreTest ((\_ -> execS w_times M.empty), (), M.fromList [("X",IntVal 0),("Y",IntVal 3),("Z",IntVal 30)]              , 5, "exec-4")
  ]
  where
    scoreTest :: (Show b, Eq b) => (a -> b, a, b, Int, String) -> TestTree
    scoreTest (f, x, r, n, msg) = scoreTest' sc (return . f, x, r, n, msg)

probParse ::  Score -> TestTree
probParse sc = testGroup "Problem 3: Parse"
  [ scoreTestI ((\_ -> parseFile "test/in/fact.imp"), (), Right w_fact, 5, "parse-1")
  , scoreTestI ((\_ -> parseFile "test/in/abs.imp"), (), Right w_abs, 5, "parse-1")
  , scoreTestI ((\_ -> parseFile "test/in/times.imp"), (), Right w_times, 5, "parse-1")
  , scoreTestI ((\_ -> parseFile "test/in/test.imp"), (), Right w_test, 5, "parse-1")
  ]
  where
    scoreTestI :: (Show b, Eq b) => (a -> IO b, a, b, Int, String) -> TestTree
    scoreTestI (f, x, r, n, msg) = scoreTest' sc (f, x, r, n, msg)
